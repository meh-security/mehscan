"""Source-only SDK/Roslyn render-facet checks; no target build or execution.

Set MEHSCAN_RAZOR_BACKEND, MEHSCAN_RAZOR_SDK and optionally MEHSCAN_DOTNET.
All target inputs travel over stdin; no fixture checkout or generated source tree.
"""
import json
import os
from pathlib import Path
import subprocess
import unittest


class RenderFacets(unittest.TestCase):
    @classmethod
    def run_frontend(cls,files,mode='--razor-facets'):
        request=dict(schema_version='1',root=str(Path(__file__).resolve().parents[3]),sdk_path=cls.sdk,
            files=[dict(path=k,text=v) for k,v in files.items()],projects=[dict(path='App.csproj',text=
                '<Project Sdk="Microsoft.NET.Sdk.Web"><PropertyGroup><RootNamespace>FacetTests</RootNamespace></PropertyGroup></Project>')])
        result=subprocess.run([*cls.command[:-1],mode],input=json.dumps(request).encode(),capture_output=True,timeout=60)
        if result.returncode:raise AssertionError(result.stderr.decode(errors='replace'))
        return json.loads(result.stdout)

    @classmethod
    def setUpClass(cls):
        backend=os.environ.get('MEHSCAN_RAZOR_BACKEND');cls.sdk=os.environ.get('MEHSCAN_RAZOR_SDK')
        if not backend or not cls.sdk:raise unittest.SkipTest('explicit Razor backend and SDK required')
        cls.command=([os.environ.get('MEHSCAN_DOTNET','dotnet'),backend] if backend.lower().endswith('.dll') else [backend])+['--razor-facets']
        cls.raw='<p>@((Microsoft.AspNetCore.Components.MarkupString)value)</p>\n@code { private string value="<b>text</b>"; }'
        cls.files={
            'Raw.razor':cls.raw,
            'Parent.razor':'<Raw />',
            'Encoded.razor':'<p>@value</p>\n@code { private string value="value"; }',
            'Getter.razor':'<p>@value</p>\n@code { private int reads; private string value { get { reads++; return "value"; } } }',
            'Call.razor':'<p>@GetValue()</p>\n@code { private string GetValue() => "value"; }',
            'Attribute.razor':'<p title="@value"></p>\n@code { private string value="value"; }',
            'Script.razor':'<script>@value</script>\n@code { private string value="value"; }',
            'Style.razor':'<style>@value</style>\n@code { private string value="value"; }',
            'Example.razor':'<p>example</p>\n@code { private const string example = """@((MarkupString)value)"""; private string value="value"; }',
            'Number.razor':'<p>@value</p>\n@code { private int value=1; }',
            'Utf8.razor':'<p>é😀 @value</p>\n@code { private string value="value"; }',
            'Fake.razor':'<p>@((FakeMarkupString)value)</p>\n@code { private string value="value"; }',
            'Context.cs':'public struct FakeMarkupString { public static explicit operator FakeMarkupString(string x) => new(); }\n'
                'public static class GenericRenderer { public static void Render<T>(Microsoft.AspNetCore.Components.Rendering.RenderTreeBuilder b) '
                'where T: Microsoft.AspNetCore.Components.IComponent { b.OpenComponent<T>(0); b.CloseComponent(); } }',
        }
        cls.output=cls.run_frontend(cls.files)
        cls.sites={}
        for site in cls.output['render_sites']:cls.sites.setdefault(site['path'],[]).append(site)

    def test_actual_framework_raw_and_encoded_sites_are_bound(self):
        self.assertEqual(self.sites['Raw.razor'][0]['mode'],'raw')
        self.assertEqual(self.sites['Encoded.razor'][0]['mode'],'encoded')

    def test_getter_and_call_operands_keep_their_operation_binding(self):
        self.assertEqual(self.sites['Getter.razor'][0]['operand'],'value')
        self.assertEqual(self.sites['Call.razor'][0]['operand'],'GetValue()')
        self.assertNotEqual(self.sites['Getter.razor'][0]['binding'],self.sites['Call.razor'][0]['binding'])

    def test_attributes_and_active_content_do_not_supply_text_local_facets(self):
        for path in ('Attribute.razor','Script.razor','Style.razor'):
            self.assertNotIn(path,self.sites,path)

    def test_documentation_strings_and_nonstring_values_are_not_admitted(self):
        for path in ('Example.razor','Number.razor','Fake.razor'):
            self.assertNotIn(path,self.sites,path)

    def test_every_mapping_binds_original_utf8_output_expression(self):
        for path,sites in self.sites.items():
            raw=self.files[path].encode()
            for site in sites:
                text=raw[site['start']:site['end']].decode()
                self.assertTrue(text.startswith('@'),text)
                self.assertIn(site['operand'],text)
                self.assertEqual(len(site['binding']),64)

    def test_encoding_switch_preserves_operand_and_binding_on_same_component(self):
        raw=self.run_frontend({'Same.razor':self.raw})['render_sites'][0]
        encoded=self.run_frontend({'Same.razor':self.raw.replace('@((Microsoft.AspNetCore.Components.MarkupString)value)','@value')})['render_sites'][0]
        self.assertEqual((raw['operand'],raw['binding']),(encoded['operand'],encoded['binding']))
        self.assertEqual((raw['mode'],encoded['mode']),('raw','encoded'))

    def test_actual_component_render_consumer_is_recorded(self):
        self.assertIn(dict(path='Parent.razor',target='Raw.razor'),self.output['render_uses'])
        self.assertIn(dict(path='Context.cs',target='*'),self.output['render_uses'])

    def test_existing_projection_mode_keeps_its_original_contract(self):
        result=self.run_frontend({'Same.razor':self.raw},mode='--razor')
        self.assertEqual(result['schema_version'],'1')
        self.assertTrue(result['projections'][0]['mappings'])
        self.assertNotIn('render_sites',result)


if __name__=='__main__':unittest.main()

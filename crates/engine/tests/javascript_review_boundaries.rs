use mehscan_engine::investigation::build_review_inventory;
use std::fs;

#[test]
fn documentation_and_client_callbacks_do_not_replace_actual_server_handlers() {
    let root =
        std::env::temp_dir().join(format!("mehscan-review-boundaries-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    fs::write(
        root.join("Controller.ts"),
        r#"
import {Controller, Post, Delete} from '@nestjs/common';
@Controller('/items')
class ItemsController {
 @Post('/reserve')
 @ApiResponse({
   schema: {
      description: 'create reservation',
      properties: { result: {example:'delete'} }
   }
 })
 @ApiOperation({description:'update selected resource'})
 async reserveSlot(input:any) {
   return this.service.createReservation(input);
 }
 @Delete('/:id')
 @ApiResponse({description:'delete response'})
 async deleteItem(id:string) { return this.service.deleteItem(id); }
}
"#,
    )
    .unwrap();
    fs::write(
        root.join("Client.tsx"),
        r#"
const updateMutation = client.update.useMutation({
 onSuccess: async (value) => { setProfile(value); },
});
const createMutation = client.create.useMutation({
 onSuccess: async () => { await saveLocalPreferences(); },
});
"#,
    )
    .unwrap();
    fs::write(
        root.join("Resolvers.ts"),
        r#"
export const resolvers = {
 Mutation: {
  updateProfile: async (parent,input,ctx) => {
    return ctx.service.updateProfile(input);
  }
 },
 Query: {
  view: async () => { return createView(); }
 }
};
const hooks = useMutation({
 onSuccess: async () => { updateUi(); }
});
"#,
    )
    .unwrap();
    fs::write(
        root.join("Routes.ts"),
        r#"
const clientMutation = {};
app.post('/items', async (req,res) => { await service.updateItem(req.body); });
"#,
    )
    .unwrap();
    let inventory = build_review_inventory(&root, false).unwrap();
    assert_eq!(inventory.scan.coverage.totals.parse_failed, 0);
    let markers = inventory
        .entries
        .iter()
        .filter(|r| r.rule_id == "framework-authorization-review-marker")
        .collect::<Vec<_>>();
    for name in ["reserveSlot", "deleteItem", "updateProfile"] {
        assert!(
            markers.iter().any(|r| r.symbol.as_deref() == Some(name)),
            "missing real handler {name}: {markers:?}"
        );
    }
    assert!(
        !markers.iter().any(|r| r.path == "Client.tsx"
            || r.symbol.as_deref() == Some("onSuccess")
            || r.symbol.as_deref() == Some("schema")),
        "spurious boundary: {markers:?}"
    );
    assert!(
        markers.iter().any(|r| r.path == "Routes.ts"),
        "HTTP route must survive nearby client Mutation text"
    );
    fs::remove_dir_all(root).unwrap();
}

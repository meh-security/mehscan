function UploadedContent({ req }: Props) {
  consume(req.file.buffer);
  return <div />;
}

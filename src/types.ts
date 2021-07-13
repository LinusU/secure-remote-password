export type Ephemeral = {
  public: string;
  secret: string;
};

export type Session = {
  key: string;
  proof: string;
};

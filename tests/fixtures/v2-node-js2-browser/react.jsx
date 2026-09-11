import React, { Component } from 'react';

export class Profile extends Component {
  constructor() {
    super();
    this.nameRef = React.createRef();
    this.websiteRef = React.createRef();
  }

  async save() {
    const request = await fetch('/profile');
    const response = await request.json();
    this.nameRef.current.innerHTML = response.name;
    this.websiteRef.current.setAttribute('href', response.website);
    this.setState({ website: response.website });
  }

  render() {
    return <a href={this.state.website} ref={this.websiteRef}>Profile</a>;
  }
}

import axios from 'axios';

export default {
  props: {
    projectId: Number,
  },

  methods: {
    async loadEndpoint(endpoint, opts) {
      return (
        await axios({
          method: 'get',
          url: endpoint,
          responseType: 'json',
          ...opts,
        })
      ).data;
    },

    async loadProjectEndpoint(endpoint, opts) {
      return this.loadEndpoint(`/api/project/${this.projectId}${endpoint}`, opts);
    },

    async loadProjectResources(name) {
      return this.loadProjectEndpoint(`/${name}`);
    },

    async loadProjectResource(name, id) {
      return this.loadProjectEndpoint(`/${name}/${id}`);
    },
  },
};

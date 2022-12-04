declare const _default: {
    type: string;
    properties: {
        id: {
            example: string;
        };
        title: {
            example: string;
        };
        order: {
            example: number;
        };
        tasks: {
            type: string;
            items: {
                type: string;
                properties: {
                    id: {
                        example: string;
                    };
                    title: {
                        example: string;
                    };
                    order: {
                        example: number;
                    };
                    done: {
                        example: boolean;
                    };
                    description: {
                        example: string;
                    };
                    userId: {
                        example: string;
                    };
                    files: {
                        type: string;
                        items: {
                            type: string;
                            properties: {
                                filename: {
                                    example: string;
                                };
                                fileSize: {
                                    example: number;
                                };
                            };
                        };
                    };
                };
            };
        };
    };
};
export default _default;

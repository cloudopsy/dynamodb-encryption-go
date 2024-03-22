package encrypted

type AttributeAction int

const (
	AttributeActionDoNothing AttributeAction = iota
	AttributeActionEncrypt
	AttributeActionEncryptDeterministically
	AttributeActionSign
)

type AttributeActions struct {
	defaultAction    AttributeAction
	attributeActions map[string]AttributeAction
}

func NewAttributeActions(defaultAction AttributeAction) *AttributeActions {
	return &AttributeActions{
		defaultAction:    defaultAction,
		attributeActions: make(map[string]AttributeAction),
	}
}

func (aa *AttributeActions) SetDefaultAction(action AttributeAction) {
	aa.defaultAction = action
}

func (aa *AttributeActions) SetAttributeAction(attributeName string, action AttributeAction) {
	aa.attributeActions[attributeName] = action
}

func (aa *AttributeActions) GetAttributeAction(attributeName string) AttributeAction {
	action, ok := aa.attributeActions[attributeName]
	if !ok {
		return aa.defaultAction
	}
	return action
}

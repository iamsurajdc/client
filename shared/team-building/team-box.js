// @flow
import React from 'react'
import Input from './input'
import UserBubble from './user-bubble'
import * as Kb from '../common-adapters'
import * as Styles from '../styles'
import type {ServiceIdWithContact} from '../constants/types/team-building'

// TODO
// * Add styles for mobile
// * handle backspace remove user

type Props = {
  onChangeText: (newText: string) => void,
  onEnterKeyDown: (textOnEnter: string) => void,
  onDownArrowKeyDown: () => void,
  onUpArrowKeyDown: () => void,
  teamSoFar: Array<{userId: string, prettyName: string, username: string, service: ServiceIdWithContact}>,
  onRemove: (userId: string) => void,
  onBackspaceWhileEmpty: () => void,
}

const TeamBox = (props: Props) => (
  <Kb.Box2 direction="horizontal" style={styles.container}>
    {props.teamSoFar.map(u => (
      <UserBubble
        key={u.userId}
        onRemove={() => props.onRemove(u.userId)}
        username={u.username}
        service={u.service}
        prettyName={u.prettyName}
      />
    ))}
    <Input
      onChangeText={props.onChangeText}
      onEnterKeyDown={props.onEnterKeyDown}
      onDownArrowKeyDown={props.onDownArrowKeyDown}
      onUpArrowKeyDown={props.onUpArrowKeyDown}
      onBackspaceWhileEmpty={() => {
        props.teamSoFar.length && props.onRemove(props.teamSoFar[props.teamSoFar.length - 1].userId)
      }}
    />
  </Kb.Box2>
)

const styles = Styles.styleSheetCreate({
  container: Styles.platformStyles({
    isElectron: {
      height: 40,
    },
    common: {
      ...Styles.globalStyles.rounded,
      borderColor: Styles.globalColors.black_20,
      borderWidth: 1,
      borderStyle: 'solid',
      flex: 1,
    },
  }),
})

export default TeamBox

import {
  DescriptionList,
  DescriptionListDescription,
  DescriptionListGroup,
  DescriptionListTerm,
} from '@patternfly/react-core';

export function Details({
  label,
  items,
}: {
  label: string;
  items: Array<{ term: string; value: string }>;
}) {
  return (
    <DescriptionList aria-label={label}>
      {items.map((item) => (
        <DescriptionListGroup key={item.term}>
          <DescriptionListTerm>{item.term}</DescriptionListTerm>
          <DescriptionListDescription>{item.value}</DescriptionListDescription>
        </DescriptionListGroup>
      ))}
    </DescriptionList>
  );
}

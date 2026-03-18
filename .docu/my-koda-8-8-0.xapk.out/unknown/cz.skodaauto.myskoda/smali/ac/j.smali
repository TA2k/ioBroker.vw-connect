.class public final Lac/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:[Lyy0/i;


# direct methods
.method public synthetic constructor <init>([Lyy0/i;I)V
    .locals 0

    .line 1
    iput p2, p0, Lac/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lac/j;->e:[Lyy0/i;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lac/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lac/j;->e:[Lyy0/i;

    .line 7
    .line 8
    array-length p0, p0

    .line 9
    new-array p0, p0, [Ljava/lang/Boolean;

    .line 10
    .line 11
    return-object p0

    .line 12
    :pswitch_0
    iget-object p0, p0, Lac/j;->e:[Lyy0/i;

    .line 13
    .line 14
    array-length p0, p0

    .line 15
    new-array p0, p0, [Lne0/s;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_1
    iget-object p0, p0, Lac/j;->e:[Lyy0/i;

    .line 19
    .line 20
    array-length p0, p0

    .line 21
    new-array p0, p0, [Lib/c;

    .line 22
    .line 23
    return-object p0

    .line 24
    :pswitch_2
    iget-object p0, p0, Lac/j;->e:[Lyy0/i;

    .line 25
    .line 26
    array-length p0, p0

    .line 27
    new-array p0, p0, [Ljava/lang/Object;

    .line 28
    .line 29
    return-object p0

    .line 30
    nop

    .line 31
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

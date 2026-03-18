.class public final synthetic Lc1/x1;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc1/w1;


# direct methods
.method public synthetic constructor <init>(Lc1/w1;I)V
    .locals 0

    .line 1
    iput p2, p0, Lc1/x1;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lc1/x1;->e:Lc1/w1;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Lc1/x1;->d:I

    .line 2
    .line 3
    check-cast p1, Landroidx/compose/runtime/DisposableEffectScope;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    new-instance p1, Lc1/y1;

    .line 9
    .line 10
    const/4 v0, 0x0

    .line 11
    iget-object p0, p0, Lc1/x1;->e:Lc1/w1;

    .line 12
    .line 13
    invoke-direct {p1, p0, v0}, Lc1/y1;-><init>(Lc1/w1;I)V

    .line 14
    .line 15
    .line 16
    return-object p1

    .line 17
    :pswitch_0
    new-instance p1, Lc1/y1;

    .line 18
    .line 19
    const/4 v0, 0x1

    .line 20
    iget-object p0, p0, Lc1/x1;->e:Lc1/w1;

    .line 21
    .line 22
    invoke-direct {p1, p0, v0}, Lc1/y1;-><init>(Lc1/w1;I)V

    .line 23
    .line 24
    .line 25
    return-object p1

    .line 26
    nop

    .line 27
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

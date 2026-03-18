.class public final synthetic Le41/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc3/j;


# direct methods
.method public synthetic constructor <init>(Lc3/j;I)V
    .locals 0

    .line 1
    iput p2, p0, Le41/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Le41/a;->e:Lc3/j;

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
    iget v0, p0, Le41/a;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iget-object p0, p0, Le41/a;->e:Lc3/j;

    .line 8
    .line 9
    check-cast p0, Lc3/l;

    .line 10
    .line 11
    invoke-virtual {p0, v0}, Lc3/l;->b(Z)V

    .line 12
    .line 13
    .line 14
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    const/4 v0, 0x1

    .line 18
    iget-object p0, p0, Le41/a;->e:Lc3/j;

    .line 19
    .line 20
    check-cast p0, Lc3/l;

    .line 21
    .line 22
    invoke-virtual {p0, v0}, Lc3/l;->b(Z)V

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :pswitch_1
    iget-object p0, p0, Le41/a;->e:Lc3/j;

    .line 27
    .line 28
    invoke-static {p0}, Lc3/j;->a(Lc3/j;)V

    .line 29
    .line 30
    .line 31
    goto :goto_0

    .line 32
    nop

    .line 33
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

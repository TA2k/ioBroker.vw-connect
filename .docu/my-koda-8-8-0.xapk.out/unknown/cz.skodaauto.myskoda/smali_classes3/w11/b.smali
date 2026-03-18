.class public final synthetic Lw11/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lx11/a;


# direct methods
.method public synthetic constructor <init>(Lx11/a;I)V
    .locals 0

    .line 1
    iput p2, p0, Lw11/b;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lw11/b;->e:Lx11/a;

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
    iget v0, p0, Lw11/b;->d:I

    .line 2
    .line 3
    iget-object p0, p0, Lw11/b;->e:Lx11/a;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    iget-object p0, p0, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 9
    .line 10
    iget-object p0, p0, Landroidx/lifecycle/c1;->g:Ljava/lang/Object;

    .line 11
    .line 12
    check-cast p0, Li21/b;

    .line 13
    .line 14
    iget-object p0, p0, Li21/b;->d:Lk21/a;

    .line 15
    .line 16
    return-object p0

    .line 17
    :pswitch_0
    iget-object p0, p0, Lx11/a;->a:Landroidx/lifecycle/c1;

    .line 18
    .line 19
    return-object p0

    .line 20
    nop

    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

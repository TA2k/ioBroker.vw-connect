.class public final synthetic Li40/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lh40/m;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lh40/m;I)V
    .locals 0

    .line 1
    iput p3, p0, Li40/g;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/g;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Li40/g;->f:Lh40/m;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Li40/g;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li40/g;->f:Lh40/m;

    .line 7
    .line 8
    iget-object v0, v0, Lh40/m;->a:Ljava/lang/String;

    .line 9
    .line 10
    iget-object p0, p0, Li40/g;->e:Lay0/k;

    .line 11
    .line 12
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 13
    .line 14
    .line 15
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 16
    .line 17
    return-object p0

    .line 18
    :pswitch_0
    iget-object v0, p0, Li40/g;->e:Lay0/k;

    .line 19
    .line 20
    iget-object p0, p0, Li40/g;->f:Lh40/m;

    .line 21
    .line 22
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    goto :goto_0

    .line 26
    :pswitch_1
    iget-object v0, p0, Li40/g;->f:Lh40/m;

    .line 27
    .line 28
    iget-object v0, v0, Lh40/m;->a:Ljava/lang/String;

    .line 29
    .line 30
    iget-object p0, p0, Li40/g;->e:Lay0/k;

    .line 31
    .line 32
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    goto :goto_0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.class public final Li40/x2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lh40/w;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lh40/w;I)V
    .locals 0

    .line 1
    iput p3, p0, Li40/x2;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li40/x2;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Li40/x2;->f:Lh40/w;

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
    iget v0, p0, Li40/x2;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Li40/x2;->e:Lay0/k;

    .line 7
    .line 8
    iget-object p0, p0, Li40/x2;->f:Lh40/w;

    .line 9
    .line 10
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 11
    .line 12
    .line 13
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 14
    .line 15
    return-object p0

    .line 16
    :pswitch_0
    iget-object v0, p0, Li40/x2;->f:Lh40/w;

    .line 17
    .line 18
    iget-object v0, v0, Lh40/w;->c:Ljava/lang/String;

    .line 19
    .line 20
    iget-object p0, p0, Li40/x2;->e:Lay0/k;

    .line 21
    .line 22
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 23
    .line 24
    .line 25
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 26
    .line 27
    return-object p0

    .line 28
    :pswitch_1
    iget-object v0, p0, Li40/x2;->e:Lay0/k;

    .line 29
    .line 30
    iget-object p0, p0, Li40/x2;->f:Lh40/w;

    .line 31
    .line 32
    invoke-interface {v0, p0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 33
    .line 34
    .line 35
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 36
    .line 37
    return-object p0

    .line 38
    :pswitch_2
    iget-object v0, p0, Li40/x2;->f:Lh40/w;

    .line 39
    .line 40
    iget-object v0, v0, Lh40/w;->c:Ljava/lang/String;

    .line 41
    .line 42
    iget-object p0, p0, Li40/x2;->e:Lay0/k;

    .line 43
    .line 44
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 45
    .line 46
    .line 47
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 48
    .line 49
    return-object p0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

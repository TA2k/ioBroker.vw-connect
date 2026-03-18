.class public final synthetic Lny/b0;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final synthetic a:I

.field public final synthetic b:Lay0/k;


# direct methods
.method public synthetic constructor <init>(ILay0/k;)V
    .locals 0

    .line 1
    iput p1, p0, Lny/b0;->a:I

    .line 2
    .line 3
    iput-object p2, p0, Lny/b0;->b:Lay0/k;

    .line 4
    .line 5
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 6
    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final a(Lz9/y;Lz9/u;)V
    .locals 0

    .line 1
    iget p1, p0, Lny/b0;->a:I

    .line 2
    .line 3
    packed-switch p1, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string p1, "destination"

    .line 7
    .line 8
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 9
    .line 10
    .line 11
    iget-object p1, p2, Lz9/u;->e:Lca/j;

    .line 12
    .line 13
    iget-object p1, p1, Lca/j;->e:Ljava/lang/Object;

    .line 14
    .line 15
    check-cast p1, Ljava/lang/String;

    .line 16
    .line 17
    iget-object p0, p0, Lny/b0;->b:Lay0/k;

    .line 18
    .line 19
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 20
    .line 21
    .line 22
    return-void

    .line 23
    :pswitch_0
    const-string p1, "destination"

    .line 24
    .line 25
    invoke-static {p2, p1}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 26
    .line 27
    .line 28
    iget-object p1, p2, Lz9/u;->e:Lca/j;

    .line 29
    .line 30
    iget-object p1, p1, Lca/j;->e:Ljava/lang/Object;

    .line 31
    .line 32
    check-cast p1, Ljava/lang/String;

    .line 33
    .line 34
    invoke-static {p1}, Lrp/d;->b(Ljava/lang/String;)Lly/b;

    .line 35
    .line 36
    .line 37
    move-result-object p1

    .line 38
    iget-object p0, p0, Lny/b0;->b:Lay0/k;

    .line 39
    .line 40
    invoke-interface {p0, p1}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 41
    .line 42
    .line 43
    return-void

    .line 44
    nop

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

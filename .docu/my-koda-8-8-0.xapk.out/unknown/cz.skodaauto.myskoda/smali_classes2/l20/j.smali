.class public final synthetic Ll20/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lc3/j;

.field public final synthetic f:Lay0/a;


# direct methods
.method public synthetic constructor <init>(Lc3/j;Lay0/a;I)V
    .locals 0

    .line 1
    iput p3, p0, Ll20/j;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Ll20/j;->e:Lc3/j;

    .line 4
    .line 5
    iput-object p2, p0, Ll20/j;->f:Lay0/a;

    .line 6
    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;)Ljava/lang/Object;
    .locals 1

    .line 1
    iget v0, p0, Ll20/j;->d:I

    .line 2
    .line 3
    check-cast p1, Lt1/m0;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$KeyboardActions"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 p1, 0x1

    .line 14
    iget-object v0, p0, Ll20/j;->e:Lc3/j;

    .line 15
    .line 16
    check-cast v0, Lc3/l;

    .line 17
    .line 18
    invoke-virtual {v0, p1}, Lc3/l;->b(Z)V

    .line 19
    .line 20
    .line 21
    iget-object p0, p0, Ll20/j;->f:Lay0/a;

    .line 22
    .line 23
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 24
    .line 25
    .line 26
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 27
    .line 28
    return-object p0

    .line 29
    :pswitch_0
    const-string v0, "$this$KeyboardActions"

    .line 30
    .line 31
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    iget-object p1, p0, Ll20/j;->e:Lc3/j;

    .line 35
    .line 36
    invoke-static {p1}, Lc3/j;->a(Lc3/j;)V

    .line 37
    .line 38
    .line 39
    iget-object p0, p0, Ll20/j;->f:Lay0/a;

    .line 40
    .line 41
    invoke-interface {p0}, Lay0/a;->invoke()Ljava/lang/Object;

    .line 42
    .line 43
    .line 44
    goto :goto_0

    .line 45
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

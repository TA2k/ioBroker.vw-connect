.class public final synthetic Lrk/d;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lay0/k;

.field public final synthetic f:Lqg/j;


# direct methods
.method public synthetic constructor <init>(Lay0/k;Lqg/j;I)V
    .locals 0

    .line 1
    iput p3, p0, Lrk/d;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Lrk/d;->e:Lay0/k;

    .line 4
    .line 5
    iput-object p2, p0, Lrk/d;->f:Lqg/j;

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
    .locals 2

    .line 1
    iget v0, p0, Lrk/d;->d:I

    .line 2
    .line 3
    check-cast p1, Ljava/lang/String;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "it"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    new-instance v0, Lqg/f;

    .line 14
    .line 15
    iget-object v1, p0, Lrk/d;->f:Lqg/j;

    .line 16
    .line 17
    iget-object v1, v1, Lqg/j;->a:Ljava/lang/String;

    .line 18
    .line 19
    invoke-direct {v0, p1, v1}, Lqg/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    iget-object p0, p0, Lrk/d;->e:Lay0/k;

    .line 23
    .line 24
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 25
    .line 26
    .line 27
    :goto_0
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 28
    .line 29
    return-object p0

    .line 30
    :pswitch_0
    const-string v0, "it"

    .line 31
    .line 32
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 33
    .line 34
    .line 35
    new-instance v0, Lqg/f;

    .line 36
    .line 37
    iget-object v1, p0, Lrk/d;->f:Lqg/j;

    .line 38
    .line 39
    iget-object v1, v1, Lqg/j;->a:Ljava/lang/String;

    .line 40
    .line 41
    invoke-direct {v0, p1, v1}, Lqg/f;-><init>(Ljava/lang/String;Ljava/lang/String;)V

    .line 42
    .line 43
    .line 44
    iget-object p0, p0, Lrk/d;->e:Lay0/k;

    .line 45
    .line 46
    invoke-interface {p0, v0}, Lay0/k;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 47
    .line 48
    .line 49
    goto :goto_0

    .line 50
    nop

    .line 51
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

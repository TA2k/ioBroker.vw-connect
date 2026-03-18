.class public final synthetic Li2/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Lt3/e1;

.field public final synthetic f:I


# direct methods
.method public synthetic constructor <init>(Lt3/e1;II)V
    .locals 0

    .line 1
    iput p3, p0, Li2/a;->d:I

    .line 2
    .line 3
    iput-object p1, p0, Li2/a;->e:Lt3/e1;

    .line 4
    .line 5
    iput p2, p0, Li2/a;->f:I

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
    iget v0, p0, Li2/a;->d:I

    .line 2
    .line 3
    check-cast p1, Lt3/d1;

    .line 4
    .line 5
    packed-switch v0, :pswitch_data_0

    .line 6
    .line 7
    .line 8
    const-string v0, "$this$layout"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p0, Li2/a;->e:Lt3/e1;

    .line 14
    .line 15
    iget v1, v0, Lt3/e1;->d:I

    .line 16
    .line 17
    div-int/lit8 v1, v1, 0x2

    .line 18
    .line 19
    iget p0, p0, Li2/a;->f:I

    .line 20
    .line 21
    sub-int/2addr p0, v1

    .line 22
    const/4 v1, 0x0

    .line 23
    invoke-static {p1, v0, p0, v1}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

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
    const-string v0, "$this$layout"

    .line 30
    .line 31
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 32
    .line 33
    .line 34
    const/4 v0, 0x0

    .line 35
    iget-object v1, p0, Li2/a;->e:Lt3/e1;

    .line 36
    .line 37
    iget p0, p0, Li2/a;->f:I

    .line 38
    .line 39
    invoke-static {p1, v1, v0, p0}, Lt3/d1;->l(Lt3/d1;Lt3/e1;II)V

    .line 40
    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_1
    iget v0, p0, Li2/a;->f:I

    .line 44
    .line 45
    neg-int v0, v0

    .line 46
    const/4 v1, 0x0

    .line 47
    iget-object p0, p0, Li2/a;->e:Lt3/e1;

    .line 48
    .line 49
    invoke-static {p1, p0, v0, v1}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 50
    .line 51
    .line 52
    goto :goto_0

    .line 53
    :pswitch_2
    const/4 v0, 0x0

    .line 54
    iget v1, p0, Li2/a;->f:I

    .line 55
    .line 56
    neg-int v1, v1

    .line 57
    iget-object p0, p0, Li2/a;->e:Lt3/e1;

    .line 58
    .line 59
    invoke-static {p1, p0, v0, v1}, Lt3/d1;->h(Lt3/d1;Lt3/e1;II)V

    .line 60
    .line 61
    .line 62
    goto :goto_0

    .line 63
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

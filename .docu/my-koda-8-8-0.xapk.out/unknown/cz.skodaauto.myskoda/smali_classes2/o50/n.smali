.class public final Lo50/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/k;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:F


# direct methods
.method public synthetic constructor <init>(IF)V
    .locals 0

    .line 1
    iput p1, p0, Lo50/n;->d:I

    .line 2
    .line 3
    iput p2, p0, Lo50/n;->e:F

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
    .locals 5

    .line 1
    iget v0, p0, Lo50/n;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lz4/e;

    .line 7
    .line 8
    const-string v0, "$this$constrainAs"

    .line 9
    .line 10
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->f(Ljava/lang/Object;Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    iget-object v0, p1, Lz4/e;->d:Ly7/k;

    .line 14
    .line 15
    iget-object v1, p1, Lz4/e;->c:Lz4/f;

    .line 16
    .line 17
    iget-object v2, v1, Lz4/f;->d:Lz4/h;

    .line 18
    .line 19
    const/4 v3, 0x0

    .line 20
    const/4 v4, 0x6

    .line 21
    invoke-static {v0, v2, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 22
    .line 23
    .line 24
    iget-object v0, p1, Lz4/e;->f:Ly7/k;

    .line 25
    .line 26
    iget-object v2, v1, Lz4/f;->f:Lz4/h;

    .line 27
    .line 28
    invoke-static {v0, v2, v3, v4}, Ly7/k;->b(Ly7/k;Lz4/h;FI)V

    .line 29
    .line 30
    .line 31
    iget-object p1, p1, Lz4/e;->e:Ly41/a;

    .line 32
    .line 33
    iget-object v0, v1, Lz4/f;->g:Lz4/g;

    .line 34
    .line 35
    iget p0, p0, Lo50/n;->e:F

    .line 36
    .line 37
    const/high16 v1, 0x3fc00000    # 1.5f

    .line 38
    .line 39
    div-float/2addr p0, v1

    .line 40
    neg-float p0, p0

    .line 41
    const/4 v1, 0x4

    .line 42
    invoke-static {p1, v0, p0, v1}, Ly41/a;->c(Ly41/a;Lz4/g;FI)V

    .line 43
    .line 44
    .line 45
    sget-object p0, Llx0/b0;->a:Llx0/b0;

    .line 46
    .line 47
    return-object p0

    .line 48
    :pswitch_0
    check-cast p1, Ljava/lang/Number;

    .line 49
    .line 50
    invoke-virtual {p1}, Ljava/lang/Number;->floatValue()F

    .line 51
    .line 52
    .line 53
    iget p0, p0, Lo50/n;->e:F

    .line 54
    .line 55
    invoke-static {p0}, Lxf0/i0;->O(F)I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    int-to-float p0, p0

    .line 60
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 61
    .line 62
    .line 63
    move-result-object p0

    .line 64
    return-object p0

    .line 65
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

.class public final synthetic Lh2/j8;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic d:I

.field public final synthetic e:Ljava/lang/Object;

.field public final synthetic f:F


# direct methods
.method public synthetic constructor <init>(FLi91/r2;)V
    .locals 1

    .line 1
    const/4 v0, 0x2

    iput v0, p0, Lh2/j8;->d:I

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    iput p1, p0, Lh2/j8;->f:F

    iput-object p2, p0, Lh2/j8;->e:Ljava/lang/Object;

    return-void
.end method

.method public synthetic constructor <init>(Lt4/c;FI)V
    .locals 0

    .line 2
    iput p3, p0, Lh2/j8;->d:I

    iput-object p1, p0, Lh2/j8;->e:Ljava/lang/Object;

    iput p2, p0, Lh2/j8;->f:F

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Lh2/j8;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object v0, p0, Lh2/j8;->e:Ljava/lang/Object;

    .line 7
    .line 8
    check-cast v0, Li91/r2;

    .line 9
    .line 10
    new-instance v1, Lt4/f;

    .line 11
    .line 12
    iget p0, p0, Lh2/j8;->f:F

    .line 13
    .line 14
    invoke-direct {v1, p0}, Lt4/f;-><init>(F)V

    .line 15
    .line 16
    .line 17
    invoke-virtual {v0}, Li91/r2;->c()Li91/s2;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    sget-object v0, Li91/s2;->e:Li91/s2;

    .line 22
    .line 23
    if-ne p0, v0, :cond_0

    .line 24
    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const/4 v1, 0x0

    .line 27
    :goto_0
    if-eqz v1, :cond_1

    .line 28
    .line 29
    iget p0, v1, Lt4/f;->d:F

    .line 30
    .line 31
    goto :goto_1

    .line 32
    :cond_1
    sget p0, Ln70/m;->c:F

    .line 33
    .line 34
    :goto_1
    sget v0, Ln70/m;->b:F

    .line 35
    .line 36
    add-float/2addr p0, v0

    .line 37
    new-instance v0, Lt4/f;

    .line 38
    .line 39
    invoke-direct {v0, p0}, Lt4/f;-><init>(F)V

    .line 40
    .line 41
    .line 42
    return-object v0

    .line 43
    :pswitch_0
    iget-object v0, p0, Lh2/j8;->e:Ljava/lang/Object;

    .line 44
    .line 45
    check-cast v0, Lt4/c;

    .line 46
    .line 47
    iget p0, p0, Lh2/j8;->f:F

    .line 48
    .line 49
    invoke-interface {v0, p0}, Lt4/c;->w0(F)F

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    :goto_2
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :pswitch_1
    iget-object v0, p0, Lh2/j8;->e:Ljava/lang/Object;

    .line 59
    .line 60
    check-cast v0, Lt4/c;

    .line 61
    .line 62
    iget p0, p0, Lh2/j8;->f:F

    .line 63
    .line 64
    invoke-interface {v0, p0}, Lt4/c;->w0(F)F

    .line 65
    .line 66
    .line 67
    move-result p0

    .line 68
    goto :goto_2

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

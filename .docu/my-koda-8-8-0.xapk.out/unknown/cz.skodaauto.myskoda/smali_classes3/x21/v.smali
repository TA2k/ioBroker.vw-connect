.class public final Lx21/v;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/a;


# instance fields
.field public final synthetic f:I

.field public final synthetic g:Lm1/t;


# direct methods
.method public synthetic constructor <init>(Lm1/t;I)V
    .locals 0

    .line 1
    iput p2, p0, Lx21/v;->f:I

    .line 2
    .line 3
    iput-object p1, p0, Lx21/v;->g:Lm1/t;

    .line 4
    .line 5
    const/4 p1, 0x0

    .line 6
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 7
    .line 8
    .line 9
    return-void
.end method


# virtual methods
.method public final invoke()Ljava/lang/Object;
    .locals 4

    .line 1
    iget v0, p0, Lx21/v;->f:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget-object p0, p0, Lx21/v;->g:Lm1/t;

    .line 7
    .line 8
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 9
    .line 10
    .line 11
    move-result-object p0

    .line 12
    iget-object p0, p0, Lm1/l;->o:Lg1/w1;

    .line 13
    .line 14
    return-object p0

    .line 15
    :pswitch_0
    iget-object p0, p0, Lx21/v;->g:Lm1/t;

    .line 16
    .line 17
    invoke-virtual {p0}, Lm1/t;->h()Lm1/l;

    .line 18
    .line 19
    .line 20
    move-result-object p0

    .line 21
    iget-object v0, p0, Lm1/l;->o:Lg1/w1;

    .line 22
    .line 23
    invoke-virtual {v0}, Ljava/lang/Enum;->ordinal()I

    .line 24
    .line 25
    .line 26
    move-result v0

    .line 27
    if-eqz v0, :cond_1

    .line 28
    .line 29
    const/4 v1, 0x1

    .line 30
    if-ne v0, v1, :cond_0

    .line 31
    .line 32
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 33
    .line 34
    .line 35
    move-result-wide v0

    .line 36
    const/16 p0, 0x20

    .line 37
    .line 38
    shr-long/2addr v0, p0

    .line 39
    :goto_0
    long-to-int p0, v0

    .line 40
    goto :goto_1

    .line 41
    :cond_0
    new-instance p0, La8/r0;

    .line 42
    .line 43
    invoke-direct {p0}, Ljava/lang/RuntimeException;-><init>()V

    .line 44
    .line 45
    .line 46
    throw p0

    .line 47
    :cond_1
    invoke-virtual {p0}, Lm1/l;->e()J

    .line 48
    .line 49
    .line 50
    move-result-wide v0

    .line 51
    const-wide v2, 0xffffffffL

    .line 52
    .line 53
    .line 54
    .line 55
    .line 56
    and-long/2addr v0, v2

    .line 57
    goto :goto_0

    .line 58
    :goto_1
    int-to-float p0, p0

    .line 59
    const v0, 0x3d4ccccd    # 0.05f

    .line 60
    .line 61
    .line 62
    mul-float/2addr p0, v0

    .line 63
    invoke-static {p0}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 64
    .line 65
    .line 66
    move-result-object p0

    .line 67
    return-object p0

    .line 68
    nop

    .line 69
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

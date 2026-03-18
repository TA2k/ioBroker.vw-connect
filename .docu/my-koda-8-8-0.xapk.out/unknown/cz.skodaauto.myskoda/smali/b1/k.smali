.class public final Lb1/k;
.super Lkotlin/jvm/internal/n;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Lay0/n;


# static fields
.field public static final g:Lb1/k;

.field public static final h:Lb1/k;


# instance fields
.field public final synthetic f:I


# direct methods
.method static synthetic constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Lb1/k;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    const/4 v2, 0x0

    .line 5
    invoke-direct {v0, v1, v2}, Lb1/k;-><init>(II)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lb1/k;->g:Lb1/k;

    .line 9
    .line 10
    new-instance v0, Lb1/k;

    .line 11
    .line 12
    const/4 v2, 0x1

    .line 13
    invoke-direct {v0, v1, v2}, Lb1/k;-><init>(II)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Lb1/k;->h:Lb1/k;

    .line 17
    .line 18
    return-void
.end method

.method public synthetic constructor <init>(II)V
    .locals 0

    .line 1
    iput p2, p0, Lb1/k;->f:I

    .line 2
    .line 3
    invoke-direct {p0, p1}, Lkotlin/jvm/internal/n;-><init>(I)V

    .line 4
    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final invoke(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;
    .locals 4

    .line 1
    iget p0, p0, Lb1/k;->f:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    check-cast p1, Lb1/i0;

    .line 7
    .line 8
    check-cast p2, Lb1/i0;

    .line 9
    .line 10
    if-ne p1, p2, :cond_0

    .line 11
    .line 12
    sget-object p0, Lb1/i0;->f:Lb1/i0;

    .line 13
    .line 14
    if-ne p2, p0, :cond_0

    .line 15
    .line 16
    const/4 p0, 0x1

    .line 17
    goto :goto_0

    .line 18
    :cond_0
    const/4 p0, 0x0

    .line 19
    :goto_0
    invoke-static {p0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 20
    .line 21
    .line 22
    move-result-object p0

    .line 23
    return-object p0

    .line 24
    :pswitch_0
    check-cast p1, Lt4/l;

    .line 25
    .line 26
    iget-wide p0, p1, Lt4/l;->a:J

    .line 27
    .line 28
    check-cast p2, Lt4/l;

    .line 29
    .line 30
    iget-wide p0, p2, Lt4/l;->a:J

    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    int-to-long p1, p0

    .line 34
    const/16 v0, 0x20

    .line 35
    .line 36
    shl-long v0, p1, v0

    .line 37
    .line 38
    const-wide v2, 0xffffffffL

    .line 39
    .line 40
    .line 41
    .line 42
    .line 43
    and-long/2addr p1, v2

    .line 44
    or-long/2addr p1, v0

    .line 45
    new-instance v0, Lt4/l;

    .line 46
    .line 47
    invoke-direct {v0, p1, p2}, Lt4/l;-><init>(J)V

    .line 48
    .line 49
    .line 50
    const/4 p1, 0x0

    .line 51
    const/high16 p2, 0x43c80000    # 400.0f

    .line 52
    .line 53
    invoke-static {p1, p2, v0, p0}, Lc1/d;->t(FFLjava/lang/Object;I)Lc1/f1;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    nop

    .line 59
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_0
    .end packed-switch
.end method

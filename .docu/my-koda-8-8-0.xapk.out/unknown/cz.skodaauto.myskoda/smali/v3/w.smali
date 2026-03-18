.class public final Lv3/w;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:F

.field public b:F

.field public c:F

.field public d:F

.field public e:F

.field public f:F

.field public g:F

.field public h:F

.field public i:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/high16 v0, 0x3f800000    # 1.0f

    .line 5
    .line 6
    iput v0, p0, Lv3/w;->a:F

    .line 7
    .line 8
    iput v0, p0, Lv3/w;->b:F

    .line 9
    .line 10
    const/high16 v0, 0x41000000    # 8.0f

    .line 11
    .line 12
    iput v0, p0, Lv3/w;->h:F

    .line 13
    .line 14
    sget v0, Le3/q0;->c:I

    .line 15
    .line 16
    sget-wide v0, Le3/q0;->b:J

    .line 17
    .line 18
    iput-wide v0, p0, Lv3/w;->i:J

    .line 19
    .line 20
    return-void
.end method

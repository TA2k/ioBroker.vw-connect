.class public final Lo8/f;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:J

.field public final b:J

.field public final c:J

.field public d:J

.field public e:J

.field public f:J

.field public g:J

.field public h:J


# direct methods
.method public constructor <init>(JJJJJJ)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lo8/f;->a:J

    .line 5
    .line 6
    iput-wide p3, p0, Lo8/f;->b:J

    .line 7
    .line 8
    move-wide p1, p3

    .line 9
    const-wide/16 p3, 0x0

    .line 10
    .line 11
    iput-wide p3, p0, Lo8/f;->d:J

    .line 12
    .line 13
    iput-wide p5, p0, Lo8/f;->e:J

    .line 14
    .line 15
    iput-wide p7, p0, Lo8/f;->f:J

    .line 16
    .line 17
    iput-wide p9, p0, Lo8/f;->g:J

    .line 18
    .line 19
    iput-wide p11, p0, Lo8/f;->c:J

    .line 20
    .line 21
    invoke-static/range {p1 .. p12}, Lo8/f;->a(JJJJJJ)J

    .line 22
    .line 23
    .line 24
    move-result-wide p1

    .line 25
    iput-wide p1, p0, Lo8/f;->h:J

    .line 26
    .line 27
    return-void
.end method

.method public static a(JJJJJJ)J
    .locals 4

    .line 1
    const-wide/16 v0, 0x1

    .line 2
    .line 3
    add-long v2, p6, v0

    .line 4
    .line 5
    cmp-long v2, v2, p8

    .line 6
    .line 7
    if-gez v2, :cond_1

    .line 8
    .line 9
    add-long v2, p2, v0

    .line 10
    .line 11
    cmp-long v2, v2, p4

    .line 12
    .line 13
    if-ltz v2, :cond_0

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :cond_0
    sub-long/2addr p0, p2

    .line 17
    sub-long v2, p8, p6

    .line 18
    .line 19
    long-to-float v2, v2

    .line 20
    sub-long/2addr p4, p2

    .line 21
    long-to-float p2, p4

    .line 22
    div-float/2addr v2, p2

    .line 23
    long-to-float p0, p0

    .line 24
    mul-float/2addr p0, v2

    .line 25
    float-to-long p0, p0

    .line 26
    const-wide/16 p2, 0x14

    .line 27
    .line 28
    div-long p2, p0, p2

    .line 29
    .line 30
    add-long/2addr p0, p6

    .line 31
    sub-long/2addr p0, p10

    .line 32
    sub-long p4, p0, p2

    .line 33
    .line 34
    sub-long/2addr p8, v0

    .line 35
    invoke-static/range {p4 .. p9}, Lw7/w;->h(JJJ)J

    .line 36
    .line 37
    .line 38
    move-result-wide p0

    .line 39
    return-wide p0

    .line 40
    :cond_1
    :goto_0
    return-wide p6
.end method

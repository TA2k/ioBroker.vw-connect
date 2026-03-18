.class public final Ldx/j;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final a:Ljava/net/URL;

.field public final b:[B

.field public c:Z

.field public final d:J

.field public final e:J


# direct methods
.method public constructor <init>(Ljava/net/URL;[B)V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Ldx/j;->a:Ljava/net/URL;

    .line 5
    .line 6
    iput-object p2, p0, Ldx/j;->b:[B

    .line 7
    .line 8
    sget-object p1, Ljava/util/concurrent/TimeUnit;->DAYS:Ljava/util/concurrent/TimeUnit;

    .line 9
    .line 10
    const-wide/16 v0, 0x7

    .line 11
    .line 12
    invoke-virtual {p1, v0, v1}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 13
    .line 14
    .line 15
    move-result-wide v0

    .line 16
    iput-wide v0, p0, Ldx/j;->d:J

    .line 17
    .line 18
    const-wide/16 v0, 0xe

    .line 19
    .line 20
    invoke-virtual {p1, v0, v1}, Ljava/util/concurrent/TimeUnit;->toMillis(J)J

    .line 21
    .line 22
    .line 23
    move-result-wide p1

    .line 24
    iput-wide p1, p0, Ldx/j;->e:J

    .line 25
    .line 26
    return-void
.end method

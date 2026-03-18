.class public final Li9/a;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J

.field public b:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const-wide v0, -0x7fffffffffffffffL    # -4.9E-324

    .line 2
    iput-wide v0, p0, Li9/a;->a:J

    .line 3
    iput-wide v0, p0, Li9/a;->b:J

    return-void
.end method

.method public constructor <init>(IJJ)V
    .locals 0

    .line 4
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 5
    iput-wide p2, p0, Li9/a;->a:J

    .line 6
    iput-wide p4, p0, Li9/a;->b:J

    return-void
.end method

.method public constructor <init>(JJ)V
    .locals 0

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-wide p1, p0, Li9/a;->a:J

    .line 9
    iput-wide p3, p0, Li9/a;->b:J

    return-void
.end method

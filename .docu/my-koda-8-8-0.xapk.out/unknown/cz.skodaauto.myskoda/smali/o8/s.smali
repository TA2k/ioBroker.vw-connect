.class public final Lo8/s;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public a:J


# direct methods
.method public constructor <init>()V
    .locals 2

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-wide/high16 v0, -0x8000000000000000L

    .line 5
    .line 6
    iput-wide v0, p0, Lo8/s;->a:J

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public a()Lt7/r;
    .locals 1

    .line 1
    new-instance v0, Lt7/r;

    .line 2
    .line 3
    invoke-direct {v0, p0}, Lt7/q;-><init>(Lo8/s;)V

    .line 4
    .line 5
    .line 6
    return-object v0
.end method

.class public final synthetic Ldm0/n;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/function/LongUnaryOperator;


# instance fields
.field public final synthetic a:J


# direct methods
.method public synthetic constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Ldm0/n;->a:J

    .line 5
    .line 6
    return-void
.end method


# virtual methods
.method public final applyAsLong(J)J
    .locals 4

    .line 1
    const-wide/32 v0, 0x927c0

    .line 2
    .line 3
    .line 4
    iget-wide v2, p0, Ldm0/n;->a:J

    .line 5
    .line 6
    sub-long v0, v2, v0

    .line 7
    .line 8
    cmp-long p0, v0, p1

    .line 9
    .line 10
    if-lez p0, :cond_0

    .line 11
    .line 12
    return-wide v2

    .line 13
    :cond_0
    return-wide p1
.end method

.class public Lnet/zetetic/database/sqlcipher/SQLiteDebug$PagerStats;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# annotations
.annotation system Ldalvik/annotation/EnclosingClass;
    value = Lnet/zetetic/database/sqlcipher/SQLiteDebug;
.end annotation

.annotation system Ldalvik/annotation/InnerClass;
    accessFlags = 0x9
    name = "PagerStats"
.end annotation


# instance fields
.field public dbStats:Ljava/util/ArrayList;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Ljava/util/ArrayList<",
            "Lnet/zetetic/database/sqlcipher/SQLiteDebug$DbStats;",
            ">;"
        }
    .end annotation
.end field

.field public largestMemAlloc:I

.field public memoryUsed:I

.field public pageCacheOverflow:I


# direct methods
.method public constructor <init>()V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    return-void
.end method

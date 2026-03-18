.class public Lcom/google/android/filament/utils/Bookmark;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field private mNativeObject:J


# direct methods
.method public constructor <init>(J)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-wide p1, p0, Lcom/google/android/filament/utils/Bookmark;->mNativeObject:J

    .line 5
    .line 6
    return-void
.end method

.method private static native nDestroyBookmark(J)V
.end method


# virtual methods
.method public finalize()V
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Bookmark;->mNativeObject:J

    .line 2
    .line 3
    invoke-static {v0, v1}, Lcom/google/android/filament/utils/Bookmark;->nDestroyBookmark(J)V

    .line 4
    .line 5
    .line 6
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 7
    .line 8
    .line 9
    return-void
.end method

.method public getNativeObject()J
    .locals 2

    .line 1
    iget-wide v0, p0, Lcom/google/android/filament/utils/Bookmark;->mNativeObject:J

    .line 2
    .line 3
    return-wide v0
.end method

.class public final Lzt/h;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lzt/h;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:J

.field public e:J


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lzg/g2;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    invoke-direct {v0, v1}, Lzg/g2;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lzt/h;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>()V
    .locals 4

    .line 1
    invoke-static {}, Lzt/h;->m()J

    move-result-wide v0

    invoke-static {}, Lzt/h;->h()J

    move-result-wide v2

    invoke-direct {p0, v0, v1, v2, v3}, Lzt/h;-><init>(JJ)V

    return-void
.end method

.method public constructor <init>(JJ)V
    .locals 0

    .line 2
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 3
    iput-wide p1, p0, Lzt/h;->d:J

    .line 4
    iput-wide p3, p0, Lzt/h;->e:J

    return-void
.end method

.method public static h()J
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->NANOSECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtimeNanos()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    return-wide v0
.end method

.method public static m()J
    .locals 3

    .line 1
    sget-object v0, Ljava/util/concurrent/TimeUnit;->MILLISECONDS:Ljava/util/concurrent/TimeUnit;

    .line 2
    .line 3
    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    .line 4
    .line 5
    .line 6
    move-result-wide v1

    .line 7
    invoke-virtual {v0, v1, v2}, Ljava/util/concurrent/TimeUnit;->toMicros(J)J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    return-wide v0
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final j()J
    .locals 4

    .line 1
    new-instance v0, Lzt/h;

    .line 2
    .line 3
    invoke-direct {v0}, Lzt/h;-><init>()V

    .line 4
    .line 5
    .line 6
    iget-wide v0, v0, Lzt/h;->e:J

    .line 7
    .line 8
    iget-wide v2, p0, Lzt/h;->e:J

    .line 9
    .line 10
    sub-long/2addr v0, v2

    .line 11
    return-wide v0
.end method

.method public final k(Lzt/h;)J
    .locals 2

    .line 1
    iget-wide v0, p1, Lzt/h;->e:J

    .line 2
    .line 3
    iget-wide p0, p0, Lzt/h;->e:J

    .line 4
    .line 5
    sub-long/2addr v0, p0

    .line 6
    return-wide v0
.end method

.method public final l()V
    .locals 2

    .line 1
    invoke-static {}, Lzt/h;->m()J

    .line 2
    .line 3
    .line 4
    move-result-wide v0

    .line 5
    iput-wide v0, p0, Lzt/h;->d:J

    .line 6
    .line 7
    invoke-static {}, Lzt/h;->h()J

    .line 8
    .line 9
    .line 10
    move-result-wide v0

    .line 11
    iput-wide v0, p0, Lzt/h;->e:J

    .line 12
    .line 13
    return-void
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-wide v0, p0, Lzt/h;->d:J

    .line 2
    .line 3
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 4
    .line 5
    .line 6
    iget-wide v0, p0, Lzt/h;->e:J

    .line 7
    .line 8
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 9
    .line 10
    .line 11
    return-void
.end method

.class public final Ll2/h1;
.super Lv2/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Lv2/m;
.implements Ll2/b1;
.implements Ll2/t2;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ll2/h1;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public e:Ll2/l2;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ll2/e1;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Ll2/e1;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Ll2/h1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(J)V
    .locals 4

    .line 1
    invoke-direct {p0}, Lv2/u;-><init>()V

    .line 2
    .line 3
    .line 4
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 5
    .line 6
    .line 7
    move-result-object v0

    .line 8
    new-instance v1, Ll2/l2;

    .line 9
    .line 10
    invoke-virtual {v0}, Lv2/f;->g()J

    .line 11
    .line 12
    .line 13
    move-result-wide v2

    .line 14
    invoke-direct {v1, v2, v3, p1, p2}, Ll2/l2;-><init>(JJ)V

    .line 15
    .line 16
    .line 17
    instance-of v0, v0, Lv2/a;

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    new-instance v0, Ll2/l2;

    .line 22
    .line 23
    const/4 v2, 0x1

    .line 24
    int-to-long v2, v2

    .line 25
    invoke-direct {v0, v2, v3, p1, p2}, Ll2/l2;-><init>(JJ)V

    .line 26
    .line 27
    .line 28
    iput-object v0, v1, Lv2/v;->b:Lv2/v;

    .line 29
    .line 30
    :cond_0
    iput-object v1, p0, Ll2/h1;->e:Ll2/l2;

    .line 31
    .line 32
    return-void
.end method


# virtual methods
.method public final c(J)V
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/h1;->e:Ll2/l2;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ll2/l2;

    .line 8
    .line 9
    iget-wide v1, v0, Ll2/l2;->c:J

    .line 10
    .line 11
    cmp-long v1, v1, p1

    .line 12
    .line 13
    if-eqz v1, :cond_0

    .line 14
    .line 15
    iget-object v1, p0, Ll2/h1;->e:Ll2/l2;

    .line 16
    .line 17
    sget-object v2, Lv2/l;->c:Ljava/lang/Object;

    .line 18
    .line 19
    monitor-enter v2

    .line 20
    :try_start_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 21
    .line 22
    .line 23
    move-result-object v3

    .line 24
    invoke-static {v1, p0, v3, v0}, Lv2/l;->o(Lv2/v;Lv2/u;Lv2/f;Lv2/v;)Lv2/v;

    .line 25
    .line 26
    .line 27
    move-result-object v0

    .line 28
    check-cast v0, Ll2/l2;

    .line 29
    .line 30
    iput-wide p1, v0, Ll2/l2;->c:J
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 31
    .line 32
    monitor-exit v2

    .line 33
    invoke-static {v3, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 34
    .line 35
    .line 36
    return-void

    .line 37
    :catchall_0
    move-exception p0

    .line 38
    monitor-exit v2

    .line 39
    throw p0

    .line 40
    :cond_0
    return-void
.end method

.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public getValue()Ljava/lang/Object;
    .locals 2

    .line 1
    iget-object v0, p0, Ll2/h1;->e:Ll2/l2;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ll2/l2;

    .line 8
    .line 9
    iget-wide v0, p0, Ll2/l2;->c:J

    .line 10
    .line 11
    invoke-static {v0, v1}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    return-object p0
.end method

.method public final j()Lay0/k;
    .locals 2

    .line 1
    new-instance v0, Li40/e1;

    .line 2
    .line 3
    const/16 v1, 0x1a

    .line 4
    .line 5
    invoke-direct {v0, p0, v1}, Li40/e1;-><init>(Ljava/lang/Object;I)V

    .line 6
    .line 7
    .line 8
    return-object v0
.end method

.method public final k()Lv2/v;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/h1;->e:Ll2/l2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Ll2/n2;
    .locals 0

    .line 1
    sget-object p0, Ll2/x0;->i:Ll2/x0;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(Lv2/v;Lv2/v;Lv2/v;)Lv2/v;
    .locals 2

    .line 1
    move-object p0, p2

    .line 2
    check-cast p0, Ll2/l2;

    .line 3
    .line 4
    check-cast p3, Ll2/l2;

    .line 5
    .line 6
    iget-wide p0, p0, Ll2/l2;->c:J

    .line 7
    .line 8
    iget-wide v0, p3, Ll2/l2;->c:J

    .line 9
    .line 10
    cmp-long p0, p0, v0

    .line 11
    .line 12
    if-nez p0, :cond_0

    .line 13
    .line 14
    return-object p2

    .line 15
    :cond_0
    const/4 p0, 0x0

    .line 16
    return-object p0
.end method

.method public final n(Lv2/v;)V
    .locals 1

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableLongStateImpl.LongStateStateRecord"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/l2;

    .line 7
    .line 8
    iput-object p1, p0, Ll2/h1;->e:Ll2/l2;

    .line 9
    .line 10
    return-void
.end method

.method public setValue(Ljava/lang/Object;)V
    .locals 2

    .line 1
    check-cast p1, Ljava/lang/Number;

    .line 2
    .line 3
    invoke-virtual {p1}, Ljava/lang/Number;->longValue()J

    .line 4
    .line 5
    .line 6
    move-result-wide v0

    .line 7
    invoke-virtual {p0, v0, v1}, Ll2/h1;->c(J)V

    .line 8
    .line 9
    .line 10
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/h1;->e:Ll2/l2;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ll2/l2;

    .line 8
    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "MutableLongState(value="

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-wide v2, v0, Ll2/l2;->c:J

    .line 17
    .line 18
    invoke-virtual {v1, v2, v3}, Ljava/lang/StringBuilder;->append(J)Ljava/lang/StringBuilder;

    .line 19
    .line 20
    .line 21
    const-string v0, ")@"

    .line 22
    .line 23
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 24
    .line 25
    .line 26
    invoke-virtual {p0}, Ljava/lang/Object;->hashCode()I

    .line 27
    .line 28
    .line 29
    move-result p0

    .line 30
    invoke-virtual {v1, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 31
    .line 32
    .line 33
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    iget-object p2, p0, Ll2/h1;->e:Ll2/l2;

    .line 2
    .line 3
    invoke-static {p2, p0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ll2/l2;

    .line 8
    .line 9
    iget-wide v0, p0, Ll2/l2;->c:J

    .line 10
    .line 11
    invoke-virtual {p1, v0, v1}, Landroid/os/Parcel;->writeLong(J)V

    .line 12
    .line 13
    .line 14
    return-void
.end method

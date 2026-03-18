.class public final Ll2/j1;
.super Lv2/u;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;
.implements Lv2/m;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Ll2/j1;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final e:Ll2/n2;

.field public f:Ll2/m2;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    .line 1
    new-instance v0, Ll2/i1;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Ll2/j1;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 7
    .line 8
    return-void
.end method

.method public constructor <init>(Ljava/lang/Object;Ll2/n2;)V
    .locals 3

    .line 1
    invoke-direct {p0}, Lv2/u;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p2, p0, Ll2/j1;->e:Ll2/n2;

    .line 5
    .line 6
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 7
    .line 8
    .line 9
    move-result-object p2

    .line 10
    new-instance v0, Ll2/m2;

    .line 11
    .line 12
    invoke-virtual {p2}, Lv2/f;->g()J

    .line 13
    .line 14
    .line 15
    move-result-wide v1

    .line 16
    invoke-direct {v0, v1, v2, p1}, Ll2/m2;-><init>(JLjava/lang/Object;)V

    .line 17
    .line 18
    .line 19
    instance-of p2, p2, Lv2/a;

    .line 20
    .line 21
    if-nez p2, :cond_0

    .line 22
    .line 23
    new-instance p2, Ll2/m2;

    .line 24
    .line 25
    const/4 v1, 0x1

    .line 26
    int-to-long v1, v1

    .line 27
    invoke-direct {p2, v1, v2, p1}, Ll2/m2;-><init>(JLjava/lang/Object;)V

    .line 28
    .line 29
    .line 30
    iput-object p2, v0, Lv2/v;->b:Lv2/v;

    .line 31
    .line 32
    :cond_0
    iput-object v0, p0, Ll2/j1;->f:Ll2/m2;

    .line 33
    .line 34
    return-void
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

.method public final getValue()Ljava/lang/Object;
    .locals 1

    .line 1
    iget-object v0, p0, Ll2/j1;->f:Ll2/m2;

    .line 2
    .line 3
    invoke-static {v0, p0}, Lv2/l;->t(Lv2/v;Lv2/t;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Ll2/m2;

    .line 8
    .line 9
    iget-object p0, p0, Ll2/m2;->c:Ljava/lang/Object;

    .line 10
    .line 11
    return-object p0
.end method

.method public final j()Lay0/k;
    .locals 2

    .line 1
    new-instance v0, Li40/e1;

    .line 2
    .line 3
    const/16 v1, 0x1b

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
    iget-object p0, p0, Ll2/j1;->f:Ll2/m2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final l()Ll2/n2;
    .locals 0

    .line 1
    iget-object p0, p0, Ll2/j1;->e:Ll2/n2;

    .line 2
    .line 3
    return-object p0
.end method

.method public final m(Lv2/v;Lv2/v;Lv2/v;)Lv2/v;
    .locals 0

    .line 1
    check-cast p1, Ll2/m2;

    .line 2
    .line 3
    move-object p1, p2

    .line 4
    check-cast p1, Ll2/m2;

    .line 5
    .line 6
    check-cast p3, Ll2/m2;

    .line 7
    .line 8
    iget-object p1, p1, Ll2/m2;->c:Ljava/lang/Object;

    .line 9
    .line 10
    iget-object p3, p3, Ll2/m2;->c:Ljava/lang/Object;

    .line 11
    .line 12
    iget-object p0, p0, Ll2/j1;->e:Ll2/n2;

    .line 13
    .line 14
    invoke-interface {p0, p1, p3}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 15
    .line 16
    .line 17
    move-result p0

    .line 18
    if-eqz p0, :cond_0

    .line 19
    .line 20
    return-object p2

    .line 21
    :cond_0
    const/4 p0, 0x0

    .line 22
    return-object p0
.end method

.method public final n(Lv2/v;)V
    .locals 1

    .line 1
    const-string v0, "null cannot be cast to non-null type androidx.compose.runtime.SnapshotMutableStateImpl.StateStateRecord<T of androidx.compose.runtime.SnapshotMutableStateImpl>"

    .line 2
    .line 3
    invoke-static {p1, v0}, Lkotlin/jvm/internal/m;->d(Ljava/lang/Object;Ljava/lang/String;)V

    .line 4
    .line 5
    .line 6
    check-cast p1, Ll2/m2;

    .line 7
    .line 8
    iput-object p1, p0, Ll2/j1;->f:Ll2/m2;

    .line 9
    .line 10
    return-void
.end method

.method public final setValue(Ljava/lang/Object;)V
    .locals 4

    .line 1
    iget-object v0, p0, Ll2/j1;->f:Ll2/m2;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ll2/m2;

    .line 8
    .line 9
    iget-object v1, p0, Ll2/j1;->e:Ll2/n2;

    .line 10
    .line 11
    iget-object v2, v0, Ll2/m2;->c:Ljava/lang/Object;

    .line 12
    .line 13
    invoke-interface {v1, v2, p1}, Ll2/n2;->a(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 14
    .line 15
    .line 16
    move-result v1

    .line 17
    if-nez v1, :cond_0

    .line 18
    .line 19
    iget-object v1, p0, Ll2/j1;->f:Ll2/m2;

    .line 20
    .line 21
    sget-object v2, Lv2/l;->c:Ljava/lang/Object;

    .line 22
    .line 23
    monitor-enter v2

    .line 24
    :try_start_0
    invoke-static {}, Lv2/l;->k()Lv2/f;

    .line 25
    .line 26
    .line 27
    move-result-object v3

    .line 28
    invoke-static {v1, p0, v3, v0}, Lv2/l;->o(Lv2/v;Lv2/u;Lv2/f;Lv2/v;)Lv2/v;

    .line 29
    .line 30
    .line 31
    move-result-object v0

    .line 32
    check-cast v0, Ll2/m2;

    .line 33
    .line 34
    iput-object p1, v0, Ll2/m2;->c:Ljava/lang/Object;
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 35
    .line 36
    monitor-exit v2

    .line 37
    invoke-static {v3, p0}, Lv2/l;->n(Lv2/f;Lv2/t;)V

    .line 38
    .line 39
    .line 40
    return-void

    .line 41
    :catchall_0
    move-exception p0

    .line 42
    monitor-exit v2

    .line 43
    throw p0

    .line 44
    :cond_0
    return-void
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget-object v0, p0, Ll2/j1;->f:Ll2/m2;

    .line 2
    .line 3
    invoke-static {v0}, Lv2/l;->i(Lv2/v;)Lv2/v;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, Ll2/m2;

    .line 8
    .line 9
    new-instance v1, Ljava/lang/StringBuilder;

    .line 10
    .line 11
    const-string v2, "MutableState(value="

    .line 12
    .line 13
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    iget-object v0, v0, Ll2/m2;->c:Ljava/lang/Object;

    .line 17
    .line 18
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

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
    .locals 0

    .line 1
    invoke-virtual {p0}, Ll2/j1;->getValue()Ljava/lang/Object;

    .line 2
    .line 3
    .line 4
    move-result-object p2

    .line 5
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeValue(Ljava/lang/Object;)V

    .line 6
    .line 7
    .line 8
    sget-object p2, Ll2/x0;->f:Ll2/x0;

    .line 9
    .line 10
    iget-object p0, p0, Ll2/j1;->e:Ll2/n2;

    .line 11
    .line 12
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 13
    .line 14
    .line 15
    move-result p2

    .line 16
    if-eqz p2, :cond_0

    .line 17
    .line 18
    const/4 p0, 0x0

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    sget-object p2, Ll2/x0;->i:Ll2/x0;

    .line 21
    .line 22
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 23
    .line 24
    .line 25
    move-result p2

    .line 26
    if-eqz p2, :cond_1

    .line 27
    .line 28
    const/4 p0, 0x1

    .line 29
    goto :goto_0

    .line 30
    :cond_1
    sget-object p2, Ll2/x0;->g:Ll2/x0;

    .line 31
    .line 32
    invoke-static {p0, p2}, Lkotlin/jvm/internal/m;->b(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 33
    .line 34
    .line 35
    move-result p0

    .line 36
    if-eqz p0, :cond_2

    .line 37
    .line 38
    const/4 p0, 0x2

    .line 39
    :goto_0
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 40
    .line 41
    .line 42
    return-void

    .line 43
    :cond_2
    new-instance p0, Ljava/lang/IllegalStateException;

    .line 44
    .line 45
    const-string p1, "Only known types of MutableState\'s SnapshotMutationPolicy are supported"

    .line 46
    .line 47
    invoke-direct {p0, p1}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 48
    .line 49
    .line 50
    throw p0
.end method

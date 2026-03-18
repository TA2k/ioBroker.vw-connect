.class public final Lcq/k;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcq/k;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:Z

.field public final f:Z

.field public final g:Z

.field public final h:Z

.field public final i:Ljava/util/List;

.field public final j:Ljava/lang/String;

.field public final k:Ljava/lang/Long;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcq/i;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Lcq/i;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcq/k;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(IZZZZLjava/util/ArrayList;Ljava/lang/String;Ljava/lang/Long;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcq/k;->d:I

    .line 5
    .line 6
    iput-boolean p2, p0, Lcq/k;->e:Z

    .line 7
    .line 8
    iput-boolean p3, p0, Lcq/k;->f:Z

    .line 9
    .line 10
    iput-boolean p4, p0, Lcq/k;->g:Z

    .line 11
    .line 12
    iput-boolean p5, p0, Lcq/k;->h:Z

    .line 13
    .line 14
    iput-object p6, p0, Lcq/k;->i:Ljava/util/List;

    .line 15
    .line 16
    iput-object p7, p0, Lcq/k;->j:Ljava/lang/String;

    .line 17
    .line 18
    iput-object p8, p0, Lcq/k;->k:Ljava/lang/Long;

    .line 19
    .line 20
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 5

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcq/k;

    .line 6
    .line 7
    const/4 v2, 0x0

    .line 8
    if-nez v1, :cond_1

    .line 9
    .line 10
    return v2

    .line 11
    :cond_1
    check-cast p1, Lcq/k;

    .line 12
    .line 13
    iget v1, p0, Lcq/k;->d:I

    .line 14
    .line 15
    iget v3, p1, Lcq/k;->d:I

    .line 16
    .line 17
    if-ne v1, v3, :cond_5

    .line 18
    .line 19
    iget-boolean v1, p0, Lcq/k;->e:Z

    .line 20
    .line 21
    iget-boolean v3, p1, Lcq/k;->e:Z

    .line 22
    .line 23
    if-ne v1, v3, :cond_5

    .line 24
    .line 25
    iget-boolean v1, p0, Lcq/k;->f:Z

    .line 26
    .line 27
    iget-boolean v3, p1, Lcq/k;->f:Z

    .line 28
    .line 29
    if-ne v1, v3, :cond_5

    .line 30
    .line 31
    iget-boolean v1, p0, Lcq/k;->g:Z

    .line 32
    .line 33
    iget-boolean v3, p1, Lcq/k;->g:Z

    .line 34
    .line 35
    if-ne v1, v3, :cond_5

    .line 36
    .line 37
    iget-boolean v1, p0, Lcq/k;->h:Z

    .line 38
    .line 39
    iget-boolean v3, p1, Lcq/k;->h:Z

    .line 40
    .line 41
    if-ne v1, v3, :cond_5

    .line 42
    .line 43
    iget-object v1, p1, Lcq/k;->i:Ljava/util/List;

    .line 44
    .line 45
    iget-object v3, p0, Lcq/k;->i:Ljava/util/List;

    .line 46
    .line 47
    if-eqz v3, :cond_3

    .line 48
    .line 49
    if-nez v1, :cond_2

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :cond_2
    invoke-interface {v3, v1}, Ljava/util/List;->containsAll(Ljava/util/Collection;)Z

    .line 53
    .line 54
    .line 55
    move-result v4

    .line 56
    if-eqz v4, :cond_5

    .line 57
    .line 58
    invoke-interface {v3}, Ljava/util/List;->size()I

    .line 59
    .line 60
    .line 61
    move-result v3

    .line 62
    invoke-interface {v1}, Ljava/util/List;->size()I

    .line 63
    .line 64
    .line 65
    move-result v1

    .line 66
    if-eq v3, v1, :cond_4

    .line 67
    .line 68
    goto :goto_1

    .line 69
    :cond_3
    :goto_0
    if-ne v3, v1, :cond_5

    .line 70
    .line 71
    :cond_4
    iget-object v1, p0, Lcq/k;->j:Ljava/lang/String;

    .line 72
    .line 73
    iget-object v3, p1, Lcq/k;->j:Ljava/lang/String;

    .line 74
    .line 75
    invoke-static {v1, v3}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 76
    .line 77
    .line 78
    move-result v1

    .line 79
    if-eqz v1, :cond_5

    .line 80
    .line 81
    iget-object p0, p0, Lcq/k;->k:Ljava/lang/Long;

    .line 82
    .line 83
    iget-object p1, p1, Lcq/k;->k:Ljava/lang/Long;

    .line 84
    .line 85
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 86
    .line 87
    .line 88
    move-result p0

    .line 89
    if-eqz p0, :cond_5

    .line 90
    .line 91
    return v0

    .line 92
    :cond_5
    :goto_1
    return v2
.end method

.method public final hashCode()I
    .locals 9

    .line 1
    iget v0, p0, Lcq/k;->d:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v1

    .line 7
    iget-boolean v0, p0, Lcq/k;->e:Z

    .line 8
    .line 9
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 10
    .line 11
    .line 12
    move-result-object v2

    .line 13
    iget-boolean v0, p0, Lcq/k;->f:Z

    .line 14
    .line 15
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 16
    .line 17
    .line 18
    move-result-object v3

    .line 19
    iget-boolean v0, p0, Lcq/k;->g:Z

    .line 20
    .line 21
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 22
    .line 23
    .line 24
    move-result-object v4

    .line 25
    iget-boolean v0, p0, Lcq/k;->h:Z

    .line 26
    .line 27
    invoke-static {v0}, Ljava/lang/Boolean;->valueOf(Z)Ljava/lang/Boolean;

    .line 28
    .line 29
    .line 30
    move-result-object v5

    .line 31
    iget-object v7, p0, Lcq/k;->j:Ljava/lang/String;

    .line 32
    .line 33
    iget-object v8, p0, Lcq/k;->k:Ljava/lang/Long;

    .line 34
    .line 35
    iget-object v6, p0, Lcq/k;->i:Ljava/util/List;

    .line 36
    .line 37
    filled-new-array/range {v1 .. v8}, [Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    move-result-object p0

    .line 41
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 42
    .line 43
    .line 44
    move-result p0

    .line 45
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 7

    .line 1
    iget-object v0, p0, Lcq/k;->i:Ljava/util/List;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lcq/k;->k:Ljava/lang/Long;

    .line 8
    .line 9
    if-eqz v1, :cond_0

    .line 10
    .line 11
    invoke-virtual {v1}, Ljava/lang/Long;->longValue()J

    .line 12
    .line 13
    .line 14
    move-result-wide v1

    .line 15
    invoke-static {v1, v2}, Ljava/time/Instant;->ofEpochMilli(J)Ljava/time/Instant;

    .line 16
    .line 17
    .line 18
    move-result-object v1

    .line 19
    goto :goto_0

    .line 20
    :cond_0
    const/4 v1, 0x0

    .line 21
    :goto_0
    invoke-static {v1}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v1

    .line 25
    new-instance v2, Ljava/lang/StringBuilder;

    .line 26
    .line 27
    const-string v3, "ConsentResponse {statusCode ="

    .line 28
    .line 29
    invoke-direct {v2, v3}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    iget v3, p0, Lcq/k;->d:I

    .line 33
    .line 34
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 35
    .line 36
    .line 37
    const-string v3, ", hasTosConsent ="

    .line 38
    .line 39
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 40
    .line 41
    .line 42
    iget-boolean v3, p0, Lcq/k;->e:Z

    .line 43
    .line 44
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Z)Ljava/lang/StringBuilder;

    .line 45
    .line 46
    .line 47
    const-string v3, ", hasLoggingConsent ="

    .line 48
    .line 49
    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    const-string v3, ", hasCloudSyncConsent ="

    .line 53
    .line 54
    const-string v4, ", hasLocationConsent ="

    .line 55
    .line 56
    iget-boolean v5, p0, Lcq/k;->f:Z

    .line 57
    .line 58
    iget-boolean v6, p0, Lcq/k;->g:Z

    .line 59
    .line 60
    invoke-static {v2, v5, v3, v6, v4}, Lkx/a;->y(Ljava/lang/StringBuilder;ZLjava/lang/String;ZLjava/lang/String;)V

    .line 61
    .line 62
    .line 63
    const-string v3, ", accountConsentRecords ="

    .line 64
    .line 65
    const-string v4, ", nodeId ="

    .line 66
    .line 67
    iget-boolean v5, p0, Lcq/k;->h:Z

    .line 68
    .line 69
    invoke-static {v3, v0, v4, v2, v5}, Lkx/a;->x(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/StringBuilder;Z)V

    .line 70
    .line 71
    .line 72
    const-string v0, ", lastUpdateRequestedTime ="

    .line 73
    .line 74
    const-string v3, "}"

    .line 75
    .line 76
    iget-object p0, p0, Lcq/k;->j:Ljava/lang/String;

    .line 77
    .line 78
    invoke-static {v2, p0, v0, v1, v3}, Lvj/b;->k(Ljava/lang/StringBuilder;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 79
    .line 80
    .line 81
    move-result-object p0

    .line 82
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 2

    .line 1
    const/16 p2, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, p2}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result p2

    .line 7
    const/4 v0, 0x1

    .line 8
    const/4 v1, 0x4

    .line 9
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 10
    .line 11
    .line 12
    iget v0, p0, Lcq/k;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 19
    .line 20
    .line 21
    iget-boolean v0, p0, Lcq/k;->e:Z

    .line 22
    .line 23
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 24
    .line 25
    .line 26
    const/4 v0, 0x3

    .line 27
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 28
    .line 29
    .line 30
    iget-boolean v0, p0, Lcq/k;->f:Z

    .line 31
    .line 32
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 33
    .line 34
    .line 35
    invoke-static {p1, v1, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 36
    .line 37
    .line 38
    iget-boolean v0, p0, Lcq/k;->g:Z

    .line 39
    .line 40
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 41
    .line 42
    .line 43
    const/4 v0, 0x5

    .line 44
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 45
    .line 46
    .line 47
    iget-boolean v0, p0, Lcq/k;->h:Z

    .line 48
    .line 49
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 50
    .line 51
    .line 52
    const/4 v0, 0x6

    .line 53
    iget-object v1, p0, Lcq/k;->i:Ljava/util/List;

    .line 54
    .line 55
    invoke-static {p1, v0, v1}, Ljp/dc;->r(Landroid/os/Parcel;ILjava/util/List;)V

    .line 56
    .line 57
    .line 58
    const/4 v0, 0x7

    .line 59
    iget-object v1, p0, Lcq/k;->j:Ljava/lang/String;

    .line 60
    .line 61
    invoke-static {p1, v1, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 62
    .line 63
    .line 64
    const/16 v0, 0x8

    .line 65
    .line 66
    iget-object p0, p0, Lcq/k;->k:Ljava/lang/Long;

    .line 67
    .line 68
    invoke-static {p1, v0, p0}, Ljp/dc;->l(Landroid/os/Parcel;ILjava/lang/Long;)V

    .line 69
    .line 70
    .line 71
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

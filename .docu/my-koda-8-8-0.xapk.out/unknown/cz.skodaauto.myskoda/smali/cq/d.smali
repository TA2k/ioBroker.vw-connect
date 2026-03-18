.class public final Lcq/d;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcq/d;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcq/e;

.field public final e:I

.field public final f:I

.field public final g:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0x19

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcq/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lcq/e;III)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lcq/d;->d:Lcq/e;

    .line 5
    .line 6
    iput p2, p0, Lcq/d;->e:I

    .line 7
    .line 8
    iput p3, p0, Lcq/d;->f:I

    .line 9
    .line 10
    iput p4, p0, Lcq/d;->g:I

    .line 11
    .line 12
    return-void
.end method


# virtual methods
.method public final toString()Ljava/lang/String;
    .locals 6

    .line 1
    iget-object v0, p0, Lcq/d;->d:Lcq/e;

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    const/4 v1, 0x3

    .line 8
    const/4 v2, 0x2

    .line 9
    iget v3, p0, Lcq/d;->e:I

    .line 10
    .line 11
    const/4 v4, 0x1

    .line 12
    if-eq v3, v4, :cond_3

    .line 13
    .line 14
    if-eq v3, v2, :cond_2

    .line 15
    .line 16
    if-eq v3, v1, :cond_1

    .line 17
    .line 18
    const/4 v5, 0x4

    .line 19
    if-eq v3, v5, :cond_0

    .line 20
    .line 21
    invoke-static {v3}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 22
    .line 23
    .line 24
    move-result-object v3

    .line 25
    goto :goto_0

    .line 26
    :cond_0
    const-string v3, "OUTPUT_CLOSED"

    .line 27
    .line 28
    goto :goto_0

    .line 29
    :cond_1
    const-string v3, "INPUT_CLOSED"

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_2
    const-string v3, "CHANNEL_CLOSED"

    .line 33
    .line 34
    goto :goto_0

    .line 35
    :cond_3
    const-string v3, "CHANNEL_OPENED"

    .line 36
    .line 37
    :goto_0
    iget v5, p0, Lcq/d;->f:I

    .line 38
    .line 39
    if-eqz v5, :cond_7

    .line 40
    .line 41
    if-eq v5, v4, :cond_6

    .line 42
    .line 43
    if-eq v5, v2, :cond_5

    .line 44
    .line 45
    if-eq v5, v1, :cond_4

    .line 46
    .line 47
    invoke-static {v5}, Ljava/lang/Integer;->toString(I)Ljava/lang/String;

    .line 48
    .line 49
    .line 50
    move-result-object v1

    .line 51
    goto :goto_1

    .line 52
    :cond_4
    const-string v1, "CLOSE_REASON_LOCAL_CLOSE"

    .line 53
    .line 54
    goto :goto_1

    .line 55
    :cond_5
    const-string v1, "CLOSE_REASON_REMOTE_CLOSE"

    .line 56
    .line 57
    goto :goto_1

    .line 58
    :cond_6
    const-string v1, "CLOSE_REASON_DISCONNECTED"

    .line 59
    .line 60
    goto :goto_1

    .line 61
    :cond_7
    const-string v1, "CLOSE_REASON_NORMAL"

    .line 62
    .line 63
    :goto_1
    const-string v2, ", type="

    .line 64
    .line 65
    const-string v4, ", closeReason="

    .line 66
    .line 67
    const-string v5, "ChannelEventParcelable[, channel="

    .line 68
    .line 69
    invoke-static {v5, v0, v2, v3, v4}, Lu/w;->k(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 70
    .line 71
    .line 72
    move-result-object v0

    .line 73
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 74
    .line 75
    .line 76
    const-string v1, ", appErrorCode="

    .line 77
    .line 78
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 79
    .line 80
    .line 81
    iget p0, p0, Lcq/d;->g:I

    .line 82
    .line 83
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 84
    .line 85
    .line 86
    const-string p0, "]"

    .line 87
    .line 88
    invoke-virtual {v0, p0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 89
    .line 90
    .line 91
    invoke-virtual {v0}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 92
    .line 93
    .line 94
    move-result-object p0

    .line 95
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x2

    .line 8
    iget-object v2, p0, Lcq/d;->d:Lcq/e;

    .line 9
    .line 10
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 11
    .line 12
    .line 13
    const/4 p2, 0x3

    .line 14
    const/4 v1, 0x4

    .line 15
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 16
    .line 17
    .line 18
    iget p2, p0, Lcq/d;->e:I

    .line 19
    .line 20
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, v1, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 24
    .line 25
    .line 26
    iget p2, p0, Lcq/d;->f:I

    .line 27
    .line 28
    invoke-virtual {p1, p2}, Landroid/os/Parcel;->writeInt(I)V

    .line 29
    .line 30
    .line 31
    const/4 p2, 0x5

    .line 32
    invoke-static {p1, p2, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 33
    .line 34
    .line 35
    iget p0, p0, Lcq/d;->g:I

    .line 36
    .line 37
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 38
    .line 39
    .line 40
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 41
    .line 42
    .line 43
    return-void
.end method

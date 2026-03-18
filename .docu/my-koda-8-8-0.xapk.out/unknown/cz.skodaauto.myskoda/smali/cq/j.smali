.class public final Lcq/j;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcq/j;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:Ljava/lang/String;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lcq/i;

    .line 2
    .line 3
    const/4 v1, 0x1

    .line 4
    invoke-direct {v0, v1}, Lcq/i;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcq/j;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(ILjava/lang/String;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput p1, p0, Lcq/j;->d:I

    .line 5
    .line 6
    iput-object p2, p0, Lcq/j;->e:Ljava/lang/String;

    .line 7
    .line 8
    return-void
.end method


# virtual methods
.method public final equals(Ljava/lang/Object;)Z
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    if-ne p0, p1, :cond_0

    .line 3
    .line 4
    return v0

    .line 5
    :cond_0
    instance-of v1, p1, Lcq/j;

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
    check-cast p1, Lcq/j;

    .line 12
    .line 13
    iget v1, p0, Lcq/j;->d:I

    .line 14
    .line 15
    iget v3, p1, Lcq/j;->d:I

    .line 16
    .line 17
    if-ne v1, v3, :cond_2

    .line 18
    .line 19
    iget-object p0, p0, Lcq/j;->e:Ljava/lang/String;

    .line 20
    .line 21
    iget-object p1, p1, Lcq/j;->e:Ljava/lang/String;

    .line 22
    .line 23
    invoke-static {p0, p1}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result p0

    .line 27
    if-eqz p0, :cond_2

    .line 28
    .line 29
    return v0

    .line 30
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 1

    .line 1
    iget v0, p0, Lcq/j;->d:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object p0, p0, Lcq/j;->e:Ljava/lang/String;

    .line 8
    .line 9
    filled-new-array {v0, p0}, [Ljava/lang/Object;

    .line 10
    .line 11
    .line 12
    move-result-object p0

    .line 13
    invoke-static {p0}, Ljava/util/Objects;->hash([Ljava/lang/Object;)I

    .line 14
    .line 15
    .line 16
    move-result p0

    .line 17
    return p0
.end method

.method public final toString()Ljava/lang/String;
    .locals 3

    .line 1
    iget v0, p0, Lcq/j;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    const-string v1, "Unrecognized state value: "

    .line 7
    .line 8
    invoke-static {v0, v1}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 9
    .line 10
    .line 11
    move-result-object v0

    .line 12
    goto :goto_0

    .line 13
    :pswitch_0
    const-string v0, "Association to watch terminated"

    .line 14
    .line 15
    goto :goto_0

    .line 16
    :pswitch_1
    const-string v0, "Accounts Matched"

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :pswitch_2
    const-string v0, "Control plane transport connected"

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :pswitch_3
    const-string v0, "Sync with old node suspended"

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :pswitch_4
    const-string v0, "Connection handshake complete"

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :pswitch_5
    const-string v0, "Connection handshake in progress"

    .line 29
    .line 30
    goto :goto_0

    .line 31
    :pswitch_6
    const-string v0, "Connected"

    .line 32
    .line 33
    goto :goto_0

    .line 34
    :pswitch_7
    const-string v0, "Unknown failure"

    .line 35
    .line 36
    goto :goto_0

    .line 37
    :pswitch_8
    const-string v0, "Accounts mismatch"

    .line 38
    .line 39
    goto :goto_0

    .line 40
    :pswitch_9
    const-string v0, "No bluetooth connection"

    .line 41
    .line 42
    goto :goto_0

    .line 43
    :pswitch_a
    const-string v0, "Did not receive connect msg"

    .line 44
    .line 45
    goto :goto_0

    .line 46
    :pswitch_b
    const-string v0, "Phone switching feature disabled"

    .line 47
    .line 48
    goto :goto_0

    .line 49
    :pswitch_c
    const-string v0, "Migration status mismatch between watch and phone"

    .line 50
    .line 51
    goto :goto_0

    .line 52
    :pswitch_d
    const-string v0, "Connect message malformed"

    .line 53
    .line 54
    goto :goto_0

    .line 55
    :pswitch_e
    const-string v0, "Another migration is already in progress"

    .line 56
    .line 57
    goto :goto_0

    .line 58
    :pswitch_f
    const-string v0, "Migration was cancelled"

    .line 59
    .line 60
    :goto_0
    const-string v1, "ConnectionStateEvent: address: "

    .line 61
    .line 62
    const-string v2, ", state: "

    .line 63
    .line 64
    iget-object p0, p0, Lcq/j;->e:Ljava/lang/String;

    .line 65
    .line 66
    invoke-static {v1, p0, v2, v0}, Lu/w;->f(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;

    .line 67
    .line 68
    .line 69
    move-result-object p0

    .line 70
    return-object p0

    .line 71
    :pswitch_data_0
    .packed-switch -0x9
        :pswitch_f
        :pswitch_e
        :pswitch_d
        :pswitch_c
        :pswitch_b
        :pswitch_a
        :pswitch_9
        :pswitch_8
        :pswitch_7
        :pswitch_6
        :pswitch_5
        :pswitch_4
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
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
    iget v0, p0, Lcq/j;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    const/4 v0, 0x2

    .line 18
    iget-object p0, p0, Lcq/j;->e:Ljava/lang/String;

    .line 19
    .line 20
    invoke-static {p1, p0, v0}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 21
    .line 22
    .line 23
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 24
    .line 25
    .line 26
    return-void
.end method

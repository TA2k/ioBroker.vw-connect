.class public Lsp/d;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lsp/d;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:I

.field public final e:Lsp/b;

.field public final f:Ljava/lang/Float;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lpp/h;

    .line 2
    .line 3
    const/16 v1, 0xf

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lpp/h;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lsp/d;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(ILsp/b;Ljava/lang/Float;)V
    .locals 4

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const/4 v0, 0x1

    .line 5
    const/4 v1, 0x0

    .line 6
    if-eqz p3, :cond_0

    .line 7
    .line 8
    invoke-virtual {p3}, Ljava/lang/Float;->floatValue()F

    .line 9
    .line 10
    .line 11
    move-result v2

    .line 12
    const/4 v3, 0x0

    .line 13
    cmpl-float v2, v2, v3

    .line 14
    .line 15
    if-lez v2, :cond_0

    .line 16
    .line 17
    move v2, v0

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    move v2, v1

    .line 20
    :goto_0
    const/4 v3, 0x3

    .line 21
    if-ne p1, v3, :cond_2

    .line 22
    .line 23
    if-eqz p2, :cond_1

    .line 24
    .line 25
    if-eqz v2, :cond_1

    .line 26
    .line 27
    :goto_1
    move p1, v3

    .line 28
    goto :goto_2

    .line 29
    :cond_1
    move v0, v1

    .line 30
    goto :goto_1

    .line 31
    :cond_2
    :goto_2
    new-instance v1, Ljava/lang/StringBuilder;

    .line 32
    .line 33
    const-string v2, "Invalid Cap: type="

    .line 34
    .line 35
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    invoke-virtual {v1, p1}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 39
    .line 40
    .line 41
    const-string v2, " bitmapDescriptor="

    .line 42
    .line 43
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 44
    .line 45
    .line 46
    invoke-virtual {v1, p2}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 47
    .line 48
    .line 49
    const-string v2, " bitmapRefWidth="

    .line 50
    .line 51
    invoke-virtual {v1, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 52
    .line 53
    .line 54
    invoke-virtual {v1, p3}, Ljava/lang/StringBuilder;->append(Ljava/lang/Object;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 58
    .line 59
    .line 60
    move-result-object v1

    .line 61
    invoke-static {v0, v1}, Lno/c0;->b(ZLjava/lang/String;)V

    .line 62
    .line 63
    .line 64
    iput p1, p0, Lsp/d;->d:I

    .line 65
    .line 66
    iput-object p2, p0, Lsp/d;->e:Lsp/b;

    .line 67
    .line 68
    iput-object p3, p0, Lsp/d;->f:Ljava/lang/Float;

    .line 69
    .line 70
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
    instance-of v1, p1, Lsp/d;

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
    check-cast p1, Lsp/d;

    .line 12
    .line 13
    iget v1, p0, Lsp/d;->d:I

    .line 14
    .line 15
    iget v3, p1, Lsp/d;->d:I

    .line 16
    .line 17
    if-ne v1, v3, :cond_2

    .line 18
    .line 19
    iget-object v1, p0, Lsp/d;->e:Lsp/b;

    .line 20
    .line 21
    iget-object v3, p1, Lsp/d;->e:Lsp/b;

    .line 22
    .line 23
    invoke-static {v1, v3}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 24
    .line 25
    .line 26
    move-result v1

    .line 27
    if-eqz v1, :cond_2

    .line 28
    .line 29
    iget-object p0, p0, Lsp/d;->f:Ljava/lang/Float;

    .line 30
    .line 31
    iget-object p1, p1, Lsp/d;->f:Ljava/lang/Float;

    .line 32
    .line 33
    invoke-static {p0, p1}, Lno/c0;->l(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 34
    .line 35
    .line 36
    move-result p0

    .line 37
    if-eqz p0, :cond_2

    .line 38
    .line 39
    return v0

    .line 40
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 2

    .line 1
    iget v0, p0, Lsp/d;->d:I

    .line 2
    .line 3
    invoke-static {v0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    iget-object v1, p0, Lsp/d;->e:Lsp/b;

    .line 8
    .line 9
    iget-object p0, p0, Lsp/d;->f:Ljava/lang/Float;

    .line 10
    .line 11
    filled-new-array {v0, v1, p0}, [Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    move-result-object p0

    .line 15
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 16
    .line 17
    .line 18
    move-result p0

    .line 19
    return p0
.end method

.method public toString()Ljava/lang/String;
    .locals 2

    .line 1
    new-instance v0, Ljava/lang/StringBuilder;

    .line 2
    .line 3
    const-string v1, "[Cap: type="

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    iget p0, p0, Lsp/d;->d:I

    .line 9
    .line 10
    const-string v1, "]"

    .line 11
    .line 12
    invoke-static {p0, v1, v0}, Lu/w;->d(ILjava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 13
    .line 14
    .line 15
    move-result-object p0

    .line 16
    return-object p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 3

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
    const/4 v0, 0x2

    .line 8
    const/4 v1, 0x4

    .line 9
    invoke-static {p1, v0, v1}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 10
    .line 11
    .line 12
    iget v0, p0, Lsp/d;->d:I

    .line 13
    .line 14
    invoke-virtual {p1, v0}, Landroid/os/Parcel;->writeInt(I)V

    .line 15
    .line 16
    .line 17
    iget-object v0, p0, Lsp/d;->e:Lsp/b;

    .line 18
    .line 19
    if-nez v0, :cond_0

    .line 20
    .line 21
    const/4 v0, 0x0

    .line 22
    goto :goto_0

    .line 23
    :cond_0
    iget-object v0, v0, Lsp/b;->a:Lyo/a;

    .line 24
    .line 25
    invoke-interface {v0}, Landroid/os/IInterface;->asBinder()Landroid/os/IBinder;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    :goto_0
    const/4 v2, 0x3

    .line 30
    invoke-static {p1, v2, v0}, Ljp/dc;->i(Landroid/os/Parcel;ILandroid/os/IBinder;)V

    .line 31
    .line 32
    .line 33
    iget-object p0, p0, Lsp/d;->f:Ljava/lang/Float;

    .line 34
    .line 35
    invoke-static {p1, v1, p0}, Ljp/dc;->h(Landroid/os/Parcel;ILjava/lang/Float;)V

    .line 36
    .line 37
    .line 38
    invoke-static {p1, p2}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 39
    .line 40
    .line 41
    return-void
.end method

.method public final x0()Lsp/d;
    .locals 5

    .line 1
    iget v0, p0, Lsp/d;->d:I

    .line 2
    .line 3
    if-eqz v0, :cond_5

    .line 4
    .line 5
    const/4 v1, 0x0

    .line 6
    const/4 v2, 0x2

    .line 7
    const/4 v3, 0x1

    .line 8
    if-eq v0, v3, :cond_4

    .line 9
    .line 10
    if-eq v0, v2, :cond_3

    .line 11
    .line 12
    const/4 v1, 0x3

    .line 13
    if-eq v0, v1, :cond_0

    .line 14
    .line 15
    new-instance v1, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    const-string v2, "Unknown Cap type: "

    .line 18
    .line 19
    invoke-direct {v1, v2}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 20
    .line 21
    .line 22
    invoke-virtual {v1, v0}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    .line 23
    .line 24
    .line 25
    invoke-virtual {v1}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 26
    .line 27
    .line 28
    move-result-object v0

    .line 29
    const-string v1, "d"

    .line 30
    .line 31
    invoke-static {v1, v0}, Landroid/util/Log;->w(Ljava/lang/String;Ljava/lang/String;)I

    .line 32
    .line 33
    .line 34
    return-object p0

    .line 35
    :cond_0
    const/4 v0, 0x0

    .line 36
    iget-object v1, p0, Lsp/d;->e:Lsp/b;

    .line 37
    .line 38
    if-eqz v1, :cond_1

    .line 39
    .line 40
    move v2, v3

    .line 41
    goto :goto_0

    .line 42
    :cond_1
    move v2, v0

    .line 43
    :goto_0
    const-string v4, "bitmapDescriptor must not be null"

    .line 44
    .line 45
    invoke-static {v4, v2}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 46
    .line 47
    .line 48
    iget-object p0, p0, Lsp/d;->f:Ljava/lang/Float;

    .line 49
    .line 50
    if-eqz p0, :cond_2

    .line 51
    .line 52
    goto :goto_1

    .line 53
    :cond_2
    move v3, v0

    .line 54
    :goto_1
    const-string v0, "bitmapRefWidth must not be null"

    .line 55
    .line 56
    invoke-static {v0, v3}, Lno/c0;->j(Ljava/lang/String;Z)V

    .line 57
    .line 58
    .line 59
    new-instance v0, Lsp/g;

    .line 60
    .line 61
    invoke-virtual {p0}, Ljava/lang/Float;->floatValue()F

    .line 62
    .line 63
    .line 64
    move-result p0

    .line 65
    invoke-direct {v0, v1, p0}, Lsp/g;-><init>(Lsp/b;F)V

    .line 66
    .line 67
    .line 68
    return-object v0

    .line 69
    :cond_3
    new-instance p0, Lsp/c;

    .line 70
    .line 71
    invoke-direct {p0, v2, v1, v1, v3}, Lsp/c;-><init>(ILsp/b;Ljava/lang/Float;I)V

    .line 72
    .line 73
    .line 74
    return-object p0

    .line 75
    :cond_4
    new-instance p0, Lsp/c;

    .line 76
    .line 77
    invoke-direct {p0, v3, v1, v1, v2}, Lsp/c;-><init>(ILsp/b;Ljava/lang/Float;I)V

    .line 78
    .line 79
    .line 80
    return-object p0

    .line 81
    :cond_5
    new-instance p0, Lsp/c;

    .line 82
    .line 83
    invoke-direct {p0}, Lsp/c;-><init>()V

    .line 84
    .line 85
    .line 86
    return-object p0
.end method

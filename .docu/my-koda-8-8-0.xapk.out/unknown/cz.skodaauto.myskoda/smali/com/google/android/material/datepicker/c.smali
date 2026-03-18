.class public final Lcom/google/android/material/datepicker/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Landroid/os/Parcelable;


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/material/datepicker/c;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public final d:Lcom/google/android/material/datepicker/b0;

.field public final e:Lcom/google/android/material/datepicker/b0;

.field public final f:Lcom/google/android/material/datepicker/b;

.field public g:Lcom/google/android/material/datepicker/b0;

.field public final h:I

.field public final i:I

.field public final j:I


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lsp/w;

    .line 2
    .line 3
    const/16 v1, 0x10

    .line 4
    .line 5
    invoke-direct {v0, v1}, Lsp/w;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lcom/google/android/material/datepicker/c;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 9
    .line 10
    return-void
.end method

.method public constructor <init>(Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/b0;Lcom/google/android/material/datepicker/b;Lcom/google/android/material/datepicker/b0;I)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    const-string v0, "start cannot be null"

    .line 5
    .line 6
    invoke-static {p1, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 7
    .line 8
    .line 9
    const-string v0, "end cannot be null"

    .line 10
    .line 11
    invoke-static {p2, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 12
    .line 13
    .line 14
    const-string v0, "validator cannot be null"

    .line 15
    .line 16
    invoke-static {p3, v0}, Ljava/util/Objects;->requireNonNull(Ljava/lang/Object;Ljava/lang/String;)Ljava/lang/Object;

    .line 17
    .line 18
    .line 19
    iput-object p1, p0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 20
    .line 21
    iput-object p2, p0, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 22
    .line 23
    iput-object p4, p0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 24
    .line 25
    iput p5, p0, Lcom/google/android/material/datepicker/c;->h:I

    .line 26
    .line 27
    iput-object p3, p0, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 28
    .line 29
    if-eqz p4, :cond_1

    .line 30
    .line 31
    iget-object p3, p1, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 32
    .line 33
    iget-object v0, p4, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 34
    .line 35
    invoke-virtual {p3, v0}, Ljava/util/Calendar;->compareTo(Ljava/util/Calendar;)I

    .line 36
    .line 37
    .line 38
    move-result p3

    .line 39
    if-gtz p3, :cond_0

    .line 40
    .line 41
    goto :goto_0

    .line 42
    :cond_0
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 43
    .line 44
    const-string p1, "start Month cannot be after current Month"

    .line 45
    .line 46
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 47
    .line 48
    .line 49
    throw p0

    .line 50
    :cond_1
    :goto_0
    if-eqz p4, :cond_3

    .line 51
    .line 52
    iget-object p3, p4, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 53
    .line 54
    iget-object p4, p2, Lcom/google/android/material/datepicker/b0;->d:Ljava/util/Calendar;

    .line 55
    .line 56
    invoke-virtual {p3, p4}, Ljava/util/Calendar;->compareTo(Ljava/util/Calendar;)I

    .line 57
    .line 58
    .line 59
    move-result p3

    .line 60
    if-gtz p3, :cond_2

    .line 61
    .line 62
    goto :goto_1

    .line 63
    :cond_2
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 64
    .line 65
    const-string p1, "current Month cannot be after end Month"

    .line 66
    .line 67
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 68
    .line 69
    .line 70
    throw p0

    .line 71
    :cond_3
    :goto_1
    if-ltz p5, :cond_4

    .line 72
    .line 73
    const/4 p3, 0x0

    .line 74
    invoke-static {p3}, Lcom/google/android/material/datepicker/n0;->g(Ljava/util/Calendar;)Ljava/util/Calendar;

    .line 75
    .line 76
    .line 77
    move-result-object p3

    .line 78
    const/4 p4, 0x7

    .line 79
    invoke-virtual {p3, p4}, Ljava/util/Calendar;->getMaximum(I)I

    .line 80
    .line 81
    .line 82
    move-result p3

    .line 83
    if-gt p5, p3, :cond_4

    .line 84
    .line 85
    invoke-virtual {p1, p2}, Lcom/google/android/material/datepicker/b0;->i(Lcom/google/android/material/datepicker/b0;)I

    .line 86
    .line 87
    .line 88
    move-result p3

    .line 89
    add-int/lit8 p3, p3, 0x1

    .line 90
    .line 91
    iput p3, p0, Lcom/google/android/material/datepicker/c;->j:I

    .line 92
    .line 93
    iget p2, p2, Lcom/google/android/material/datepicker/b0;->f:I

    .line 94
    .line 95
    iget p1, p1, Lcom/google/android/material/datepicker/b0;->f:I

    .line 96
    .line 97
    sub-int/2addr p2, p1

    .line 98
    add-int/lit8 p2, p2, 0x1

    .line 99
    .line 100
    iput p2, p0, Lcom/google/android/material/datepicker/c;->i:I

    .line 101
    .line 102
    return-void

    .line 103
    :cond_4
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 104
    .line 105
    const-string p1, "firstDayOfWeek is not valid"

    .line 106
    .line 107
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 108
    .line 109
    .line 110
    throw p0
.end method


# virtual methods
.method public final describeContents()I
    .locals 0

    .line 1
    const/4 p0, 0x0

    .line 2
    return p0
.end method

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
    instance-of v1, p1, Lcom/google/android/material/datepicker/c;

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
    check-cast p1, Lcom/google/android/material/datepicker/c;

    .line 12
    .line 13
    iget-object v1, p0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 14
    .line 15
    iget-object v3, p1, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 16
    .line 17
    invoke-virtual {v1, v3}, Lcom/google/android/material/datepicker/b0;->equals(Ljava/lang/Object;)Z

    .line 18
    .line 19
    .line 20
    move-result v1

    .line 21
    if-eqz v1, :cond_2

    .line 22
    .line 23
    iget-object v1, p0, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 24
    .line 25
    iget-object v3, p1, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 26
    .line 27
    invoke-virtual {v1, v3}, Lcom/google/android/material/datepicker/b0;->equals(Ljava/lang/Object;)Z

    .line 28
    .line 29
    .line 30
    move-result v1

    .line 31
    if-eqz v1, :cond_2

    .line 32
    .line 33
    iget-object v1, p0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 34
    .line 35
    iget-object v3, p1, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 36
    .line 37
    invoke-static {v1, v3}, Ljava/util/Objects;->equals(Ljava/lang/Object;Ljava/lang/Object;)Z

    .line 38
    .line 39
    .line 40
    move-result v1

    .line 41
    if-eqz v1, :cond_2

    .line 42
    .line 43
    iget v1, p0, Lcom/google/android/material/datepicker/c;->h:I

    .line 44
    .line 45
    iget v3, p1, Lcom/google/android/material/datepicker/c;->h:I

    .line 46
    .line 47
    if-ne v1, v3, :cond_2

    .line 48
    .line 49
    iget-object p0, p0, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 50
    .line 51
    iget-object p1, p1, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 52
    .line 53
    invoke-virtual {p0, p1}, Ljava/lang/Object;->equals(Ljava/lang/Object;)Z

    .line 54
    .line 55
    .line 56
    move-result p0

    .line 57
    if-eqz p0, :cond_2

    .line 58
    .line 59
    return v0

    .line 60
    :cond_2
    return v2
.end method

.method public final hashCode()I
    .locals 4

    .line 1
    iget-object v0, p0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 2
    .line 3
    iget v1, p0, Lcom/google/android/material/datepicker/c;->h:I

    .line 4
    .line 5
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    iget-object v2, p0, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 10
    .line 11
    iget-object v3, p0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 12
    .line 13
    iget-object p0, p0, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 14
    .line 15
    filled-new-array {v3, p0, v0, v1, v2}, [Ljava/lang/Object;

    .line 16
    .line 17
    .line 18
    move-result-object p0

    .line 19
    invoke-static {p0}, Ljava/util/Arrays;->hashCode([Ljava/lang/Object;)I

    .line 20
    .line 21
    .line 22
    move-result p0

    .line 23
    return p0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 1

    .line 1
    iget-object p2, p0, Lcom/google/android/material/datepicker/c;->d:Lcom/google/android/material/datepicker/b0;

    .line 2
    .line 3
    const/4 v0, 0x0

    .line 4
    invoke-virtual {p1, p2, v0}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 5
    .line 6
    .line 7
    iget-object p2, p0, Lcom/google/android/material/datepicker/c;->e:Lcom/google/android/material/datepicker/b0;

    .line 8
    .line 9
    invoke-virtual {p1, p2, v0}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 10
    .line 11
    .line 12
    iget-object p2, p0, Lcom/google/android/material/datepicker/c;->g:Lcom/google/android/material/datepicker/b0;

    .line 13
    .line 14
    invoke-virtual {p1, p2, v0}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 15
    .line 16
    .line 17
    iget-object p2, p0, Lcom/google/android/material/datepicker/c;->f:Lcom/google/android/material/datepicker/b;

    .line 18
    .line 19
    invoke-virtual {p1, p2, v0}, Landroid/os/Parcel;->writeParcelable(Landroid/os/Parcelable;I)V

    .line 20
    .line 21
    .line 22
    iget p0, p0, Lcom/google/android/material/datepicker/c;->h:I

    .line 23
    .line 24
    invoke-virtual {p1, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

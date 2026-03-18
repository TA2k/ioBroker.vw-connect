.class public final Landroidx/datastore/preferences/protobuf/e;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/util/Iterator;


# instance fields
.field public final synthetic d:I

.field public e:I

.field public final f:I

.field public final synthetic g:Ljava/lang/Object;


# direct methods
.method public constructor <init>(Landroidx/datastore/preferences/protobuf/h;)V
    .locals 1

    const/4 v0, 0x0

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 7
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 8
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 9
    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 10
    invoke-virtual {p1}, Landroidx/datastore/preferences/protobuf/h;->size()I

    move-result p1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    return-void
.end method

.method public constructor <init>(Landroidx/glance/appwidget/protobuf/g;)V
    .locals 1

    const/4 v0, 0x1

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 11
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 12
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 13
    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 14
    invoke-virtual {p1}, Landroidx/glance/appwidget/protobuf/g;->size()I

    move-result p1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    return-void
.end method

.method public constructor <init>(Lcom/google/android/gms/internal/measurement/a5;)V
    .locals 1

    const/4 v0, 0x2

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    const/4 v0, 0x0

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    invoke-virtual {p1}, Lcom/google/android/gms/internal/measurement/a5;->g()I

    move-result p1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    return-void
.end method

.method public constructor <init>(Lcom/google/crypto/tink/shaded/protobuf/i;)V
    .locals 1

    const/4 v0, 0x3

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 15
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 16
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 17
    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 18
    invoke-virtual {p1}, Lcom/google/crypto/tink/shaded/protobuf/i;->size()I

    move-result p1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    return-void
.end method

.method public constructor <init>(Lcom/google/protobuf/e;)V
    .locals 1

    const/4 v0, 0x4

    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    iput-object p1, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    const/4 v0, 0x0

    .line 5
    iput v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 6
    invoke-virtual {p1}, Lcom/google/protobuf/e;->size()I

    move-result p1

    iput p1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    return-void
.end method


# virtual methods
.method public final hasNext()Z
    .locals 1

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 7
    .line 8
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 9
    .line 10
    if-ge v0, p0, :cond_0

    .line 11
    .line 12
    const/4 p0, 0x1

    .line 13
    goto :goto_0

    .line 14
    :cond_0
    const/4 p0, 0x0

    .line 15
    :goto_0
    return p0

    .line 16
    :pswitch_0
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 17
    .line 18
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 19
    .line 20
    if-ge v0, p0, :cond_1

    .line 21
    .line 22
    const/4 p0, 0x1

    .line 23
    goto :goto_1

    .line 24
    :cond_1
    const/4 p0, 0x0

    .line 25
    :goto_1
    return p0

    .line 26
    :pswitch_1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 27
    .line 28
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 29
    .line 30
    if-ge v0, p0, :cond_2

    .line 31
    .line 32
    const/4 p0, 0x1

    .line 33
    goto :goto_2

    .line 34
    :cond_2
    const/4 p0, 0x0

    .line 35
    :goto_2
    return p0

    .line 36
    :pswitch_2
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 37
    .line 38
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 39
    .line 40
    if-ge v0, p0, :cond_3

    .line 41
    .line 42
    const/4 p0, 0x1

    .line 43
    goto :goto_3

    .line 44
    :cond_3
    const/4 p0, 0x0

    .line 45
    :goto_3
    return p0

    .line 46
    :pswitch_3
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 47
    .line 48
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 49
    .line 50
    if-ge v0, p0, :cond_4

    .line 51
    .line 52
    const/4 p0, 0x1

    .line 53
    goto :goto_4

    .line 54
    :cond_4
    const/4 p0, 0x0

    .line 55
    :goto_4
    return p0

    .line 56
    nop

    .line 57
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final next()Ljava/lang/Object;
    .locals 2

    .line 1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 2
    .line 3
    packed-switch v0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 7
    .line 8
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 9
    .line 10
    if-ge v0, v1, :cond_0

    .line 11
    .line 12
    add-int/lit8 v1, v0, 0x1

    .line 13
    .line 14
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 15
    .line 16
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 17
    .line 18
    check-cast p0, Lcom/google/protobuf/e;

    .line 19
    .line 20
    invoke-virtual {p0, v0}, Lcom/google/protobuf/e;->i(I)B

    .line 21
    .line 22
    .line 23
    move-result p0

    .line 24
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 25
    .line 26
    .line 27
    move-result-object p0

    .line 28
    return-object p0

    .line 29
    :cond_0
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 30
    .line 31
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 32
    .line 33
    .line 34
    throw p0

    .line 35
    :pswitch_0
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 36
    .line 37
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 38
    .line 39
    if-ge v0, v1, :cond_1

    .line 40
    .line 41
    add-int/lit8 v1, v0, 0x1

    .line 42
    .line 43
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 44
    .line 45
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 46
    .line 47
    check-cast p0, Lcom/google/crypto/tink/shaded/protobuf/i;

    .line 48
    .line 49
    invoke-virtual {p0, v0}, Lcom/google/crypto/tink/shaded/protobuf/i;->k(I)B

    .line 50
    .line 51
    .line 52
    move-result p0

    .line 53
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 54
    .line 55
    .line 56
    move-result-object p0

    .line 57
    return-object p0

    .line 58
    :cond_1
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 59
    .line 60
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 61
    .line 62
    .line 63
    throw p0

    .line 64
    :pswitch_1
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 65
    .line 66
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 67
    .line 68
    if-ge v0, v1, :cond_2

    .line 69
    .line 70
    add-int/lit8 v1, v0, 0x1

    .line 71
    .line 72
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 73
    .line 74
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 75
    .line 76
    check-cast p0, Lcom/google/android/gms/internal/measurement/a5;

    .line 77
    .line 78
    invoke-virtual {p0, v0}, Lcom/google/android/gms/internal/measurement/a5;->e(I)B

    .line 79
    .line 80
    .line 81
    move-result p0

    .line 82
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 83
    .line 84
    .line 85
    move-result-object p0

    .line 86
    return-object p0

    .line 87
    :cond_2
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 88
    .line 89
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 90
    .line 91
    .line 92
    throw p0

    .line 93
    :pswitch_2
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 94
    .line 95
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 96
    .line 97
    if-ge v0, v1, :cond_3

    .line 98
    .line 99
    add-int/lit8 v1, v0, 0x1

    .line 100
    .line 101
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 102
    .line 103
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 104
    .line 105
    check-cast p0, Landroidx/glance/appwidget/protobuf/g;

    .line 106
    .line 107
    invoke-virtual {p0, v0}, Landroidx/glance/appwidget/protobuf/g;->k(I)B

    .line 108
    .line 109
    .line 110
    move-result p0

    .line 111
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 112
    .line 113
    .line 114
    move-result-object p0

    .line 115
    return-object p0

    .line 116
    :cond_3
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 117
    .line 118
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 119
    .line 120
    .line 121
    throw p0

    .line 122
    :pswitch_3
    iget v0, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 123
    .line 124
    iget v1, p0, Landroidx/datastore/preferences/protobuf/e;->f:I

    .line 125
    .line 126
    if-ge v0, v1, :cond_4

    .line 127
    .line 128
    add-int/lit8 v1, v0, 0x1

    .line 129
    .line 130
    iput v1, p0, Landroidx/datastore/preferences/protobuf/e;->e:I

    .line 131
    .line 132
    iget-object p0, p0, Landroidx/datastore/preferences/protobuf/e;->g:Ljava/lang/Object;

    .line 133
    .line 134
    check-cast p0, Landroidx/datastore/preferences/protobuf/h;

    .line 135
    .line 136
    invoke-virtual {p0, v0}, Landroidx/datastore/preferences/protobuf/h;->m(I)B

    .line 137
    .line 138
    .line 139
    move-result p0

    .line 140
    invoke-static {p0}, Ljava/lang/Byte;->valueOf(B)Ljava/lang/Byte;

    .line 141
    .line 142
    .line 143
    move-result-object p0

    .line 144
    return-object p0

    .line 145
    :cond_4
    new-instance p0, Ljava/util/NoSuchElementException;

    .line 146
    .line 147
    invoke-direct {p0}, Ljava/util/NoSuchElementException;-><init>()V

    .line 148
    .line 149
    .line 150
    throw p0

    .line 151
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

.method public final remove()V
    .locals 0

    .line 1
    iget p0, p0, Landroidx/datastore/preferences/protobuf/e;->d:I

    .line 2
    .line 3
    packed-switch p0, :pswitch_data_0

    .line 4
    .line 5
    .line 6
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 7
    .line 8
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 9
    .line 10
    .line 11
    throw p0

    .line 12
    :pswitch_0
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 13
    .line 14
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 15
    .line 16
    .line 17
    throw p0

    .line 18
    :pswitch_1
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 19
    .line 20
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 21
    .line 22
    .line 23
    throw p0

    .line 24
    :pswitch_2
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 25
    .line 26
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 27
    .line 28
    .line 29
    throw p0

    .line 30
    :pswitch_3
    new-instance p0, Ljava/lang/UnsupportedOperationException;

    .line 31
    .line 32
    invoke-direct {p0}, Ljava/lang/UnsupportedOperationException;-><init>()V

    .line 33
    .line 34
    .line 35
    throw p0

    .line 36
    nop

    .line 37
    :pswitch_data_0
    .packed-switch 0x0
        :pswitch_3
        :pswitch_2
        :pswitch_1
        :pswitch_0
    .end packed-switch
.end method

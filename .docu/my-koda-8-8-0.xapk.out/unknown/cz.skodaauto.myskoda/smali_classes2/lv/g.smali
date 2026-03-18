.class public final Llv/g;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Llv/f;


# static fields
.field public static final h:Ljp/c0;


# instance fields
.field public a:Z

.field public b:Z

.field public c:Z

.field public final d:Landroid/content/Context;

.field public final e:Lhv/b;

.field public final f:Ljp/vg;

.field public g:Ljp/nh;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Ljp/y;->e:Ljp/w;

    .line 2
    .line 3
    const-string v0, "com.google.android.gms.vision.barcode"

    .line 4
    .line 5
    const-string v1, "com.google.android.gms.tflite_dynamite"

    .line 6
    .line 7
    filled-new-array {v0, v1}, [Ljava/lang/Object;

    .line 8
    .line 9
    .line 10
    move-result-object v0

    .line 11
    const/4 v1, 0x0

    .line 12
    :goto_0
    const/4 v2, 0x2

    .line 13
    if-ge v1, v2, :cond_1

    .line 14
    .line 15
    aget-object v2, v0, v1

    .line 16
    .line 17
    if-eqz v2, :cond_0

    .line 18
    .line 19
    add-int/lit8 v1, v1, 0x1

    .line 20
    .line 21
    goto :goto_0

    .line 22
    :cond_0
    new-instance v0, Ljava/lang/NullPointerException;

    .line 23
    .line 24
    const-string v2, "at index "

    .line 25
    .line 26
    invoke-static {v1, v2}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 27
    .line 28
    .line 29
    move-result-object v1

    .line 30
    invoke-direct {v0, v1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    throw v0

    .line 34
    :cond_1
    new-instance v1, Ljp/c0;

    .line 35
    .line 36
    invoke-direct {v1, v0, v2}, Ljp/c0;-><init>([Ljava/lang/Object;I)V

    .line 37
    .line 38
    .line 39
    sput-object v1, Llv/g;->h:Ljp/c0;

    .line 40
    .line 41
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lhv/b;Ljp/vg;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Llv/g;->d:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Llv/g;->e:Lhv/b;

    .line 7
    .line 8
    iput-object p3, p0, Llv/g;->f:Ljp/vg;

    .line 9
    .line 10
    return-void
.end method


# virtual methods
.method public final a(Lmv/a;)Ljava/util/ArrayList;
    .locals 9

    .line 1
    iget-object v0, p0, Llv/g;->g:Ljp/nh;

    .line 2
    .line 3
    if-nez v0, :cond_0

    .line 4
    .line 5
    invoke-virtual {p0}, Llv/g;->j()Z

    .line 6
    .line 7
    .line 8
    :cond_0
    iget-object v0, p0, Llv/g;->g:Ljp/nh;

    .line 9
    .line 10
    invoke-static {v0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 11
    .line 12
    .line 13
    iget-boolean v1, p0, Llv/g;->a:Z

    .line 14
    .line 15
    const/4 v2, 0x1

    .line 16
    if-nez v1, :cond_1

    .line 17
    .line 18
    :try_start_0
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 19
    .line 20
    .line 21
    move-result-object v1

    .line 22
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V

    .line 23
    .line 24
    .line 25
    iput-boolean v2, p0, Llv/g;->a:Z
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 26
    .line 27
    goto :goto_0

    .line 28
    :catch_0
    move-exception p0

    .line 29
    new-instance p1, Lbv/a;

    .line 30
    .line 31
    const-string v0, "Failed to init barcode scanner."

    .line 32
    .line 33
    invoke-direct {p1, v0, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 34
    .line 35
    .line 36
    throw p1

    .line 37
    :cond_1
    :goto_0
    iget p0, p1, Lmv/a;->c:I

    .line 38
    .line 39
    iget v1, p1, Lmv/a;->f:I

    .line 40
    .line 41
    const/16 v3, 0x23

    .line 42
    .line 43
    if-ne v1, v3, :cond_2

    .line 44
    .line 45
    invoke-virtual {p1}, Lmv/a;->b()[Landroid/media/Image$Plane;

    .line 46
    .line 47
    .line 48
    move-result-object p0

    .line 49
    invoke-static {p0}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 50
    .line 51
    .line 52
    const/4 v3, 0x0

    .line 53
    aget-object p0, p0, v3

    .line 54
    .line 55
    invoke-virtual {p0}, Landroid/media/Image$Plane;->getRowStride()I

    .line 56
    .line 57
    .line 58
    move-result p0

    .line 59
    :cond_2
    iget v3, p1, Lmv/a;->d:I

    .line 60
    .line 61
    iget v4, p1, Lmv/a;->e:I

    .line 62
    .line 63
    invoke-static {v4}, Ljp/xa;->a(I)I

    .line 64
    .line 65
    .line 66
    move-result v4

    .line 67
    invoke-static {}, Landroid/os/SystemClock;->elapsedRealtime()J

    .line 68
    .line 69
    .line 70
    move-result-wide v5

    .line 71
    invoke-static {p1}, Lnv/d;->a(Lmv/a;)Lyo/b;

    .line 72
    .line 73
    .line 74
    move-result-object p1

    .line 75
    :try_start_1
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 76
    .line 77
    .line 78
    move-result-object v7

    .line 79
    sget v8, Ljp/q;->a:I

    .line 80
    .line 81
    invoke-virtual {v7, p1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 82
    .line 83
    .line 84
    invoke-virtual {v7, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 85
    .line 86
    .line 87
    const/16 p1, 0x4f45

    .line 88
    .line 89
    invoke-static {v7, p1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 90
    .line 91
    .line 92
    move-result p1

    .line 93
    const/4 v8, 0x4

    .line 94
    invoke-static {v7, v2, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 95
    .line 96
    .line 97
    invoke-virtual {v7, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 98
    .line 99
    .line 100
    const/4 v1, 0x2

    .line 101
    invoke-static {v7, v1, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 102
    .line 103
    .line 104
    invoke-virtual {v7, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 105
    .line 106
    .line 107
    const/4 p0, 0x3

    .line 108
    invoke-static {v7, p0, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 109
    .line 110
    .line 111
    invoke-virtual {v7, v3}, Landroid/os/Parcel;->writeInt(I)V

    .line 112
    .line 113
    .line 114
    invoke-static {v7, v8, v8}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 115
    .line 116
    .line 117
    invoke-virtual {v7, v4}, Landroid/os/Parcel;->writeInt(I)V

    .line 118
    .line 119
    .line 120
    const/4 v1, 0x5

    .line 121
    const/16 v2, 0x8

    .line 122
    .line 123
    invoke-static {v7, v1, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 124
    .line 125
    .line 126
    invoke-virtual {v7, v5, v6}, Landroid/os/Parcel;->writeLong(J)V

    .line 127
    .line 128
    .line 129
    invoke-static {v7, p1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 130
    .line 131
    .line 132
    invoke-virtual {v0, v7, p0}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 133
    .line 134
    .line 135
    move-result-object p0

    .line 136
    sget-object p1, Ljp/mh;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 137
    .line 138
    invoke-virtual {p0, p1}, Landroid/os/Parcel;->createTypedArrayList(Landroid/os/Parcelable$Creator;)Ljava/util/ArrayList;

    .line 139
    .line 140
    .line 141
    move-result-object p1

    .line 142
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V
    :try_end_1
    .catch Landroid/os/RemoteException; {:try_start_1 .. :try_end_1} :catch_1

    .line 143
    .line 144
    .line 145
    new-instance p0, Ljava/util/ArrayList;

    .line 146
    .line 147
    invoke-direct {p0}, Ljava/util/ArrayList;-><init>()V

    .line 148
    .line 149
    .line 150
    invoke-interface {p1}, Ljava/util/List;->iterator()Ljava/util/Iterator;

    .line 151
    .line 152
    .line 153
    move-result-object p1

    .line 154
    :goto_1
    invoke-interface {p1}, Ljava/util/Iterator;->hasNext()Z

    .line 155
    .line 156
    .line 157
    move-result v0

    .line 158
    if-eqz v0, :cond_3

    .line 159
    .line 160
    invoke-interface {p1}, Ljava/util/Iterator;->next()Ljava/lang/Object;

    .line 161
    .line 162
    .line 163
    move-result-object v0

    .line 164
    check-cast v0, Ljp/mh;

    .line 165
    .line 166
    new-instance v1, Ljv/a;

    .line 167
    .line 168
    new-instance v2, Lh6/e;

    .line 169
    .line 170
    const/16 v3, 0x13

    .line 171
    .line 172
    invoke-direct {v2, v0, v3}, Lh6/e;-><init>(Ljava/lang/Object;I)V

    .line 173
    .line 174
    .line 175
    invoke-direct {v1, v2}, Ljv/a;-><init>(Lkv/a;)V

    .line 176
    .line 177
    .line 178
    invoke-virtual {p0, v1}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 179
    .line 180
    .line 181
    goto :goto_1

    .line 182
    :cond_3
    return-object p0

    .line 183
    :catch_1
    move-exception p0

    .line 184
    new-instance p1, Lbv/a;

    .line 185
    .line 186
    const-string v0, "Failed to run barcode scanner."

    .line 187
    .line 188
    invoke-direct {p1, v0, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 189
    .line 190
    .line 191
    throw p1
.end method

.method public final b(Lzo/c;Ljava/lang/String;Ljava/lang/String;)Ljp/nh;
    .locals 4

    .line 1
    iget-object v0, p0, Llv/g;->d:Landroid/content/Context;

    .line 2
    .line 3
    invoke-static {v0, p1, p2}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;

    .line 4
    .line 5
    .line 6
    move-result-object p1

    .line 7
    invoke-virtual {p1, p3}, Lzo/d;->b(Ljava/lang/String;)Landroid/os/IBinder;

    .line 8
    .line 9
    .line 10
    move-result-object p1

    .line 11
    sget p2, Ljp/ph;->d:I

    .line 12
    .line 13
    const/4 p2, 0x6

    .line 14
    const/4 p3, 0x0

    .line 15
    if-nez p1, :cond_0

    .line 16
    .line 17
    move-object v2, p3

    .line 18
    goto :goto_0

    .line 19
    :cond_0
    const-string v1, "com.google.mlkit.vision.barcode.aidls.IBarcodeScannerCreator"

    .line 20
    .line 21
    invoke-interface {p1, v1}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 22
    .line 23
    .line 24
    move-result-object v2

    .line 25
    instance-of v3, v2, Ljp/qh;

    .line 26
    .line 27
    if-eqz v3, :cond_1

    .line 28
    .line 29
    check-cast v2, Ljp/qh;

    .line 30
    .line 31
    goto :goto_0

    .line 32
    :cond_1
    new-instance v2, Ljp/oh;

    .line 33
    .line 34
    invoke-direct {v2, p1, v1, p2}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 35
    .line 36
    .line 37
    :goto_0
    new-instance p1, Lyo/b;

    .line 38
    .line 39
    invoke-direct {p1, v0}, Lyo/b;-><init>(Ljava/lang/Object;)V

    .line 40
    .line 41
    .line 42
    iget-object p0, p0, Llv/g;->e:Lhv/b;

    .line 43
    .line 44
    iget p0, p0, Lhv/b;->a:I

    .line 45
    .line 46
    check-cast v2, Ljp/oh;

    .line 47
    .line 48
    invoke-virtual {v2}, Lbp/a;->S()Landroid/os/Parcel;

    .line 49
    .line 50
    .line 51
    move-result-object v0

    .line 52
    sget v1, Ljp/q;->a:I

    .line 53
    .line 54
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeStrongBinder(Landroid/os/IBinder;)V

    .line 55
    .line 56
    .line 57
    const/4 p1, 0x1

    .line 58
    invoke-virtual {v0, p1}, Landroid/os/Parcel;->writeInt(I)V

    .line 59
    .line 60
    .line 61
    const/16 v1, 0x4f45

    .line 62
    .line 63
    invoke-static {v0, v1}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 64
    .line 65
    .line 66
    move-result v1

    .line 67
    const/4 v3, 0x4

    .line 68
    invoke-static {v0, p1, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 72
    .line 73
    .line 74
    const/4 p0, 0x2

    .line 75
    invoke-static {v0, p0, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 76
    .line 77
    .line 78
    const/4 p0, 0x0

    .line 79
    invoke-virtual {v0, p0}, Landroid/os/Parcel;->writeInt(I)V

    .line 80
    .line 81
    .line 82
    invoke-static {v0, v1}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 83
    .line 84
    .line 85
    invoke-virtual {v2, v0, p1}, Lbp/a;->T(Landroid/os/Parcel;I)Landroid/os/Parcel;

    .line 86
    .line 87
    .line 88
    move-result-object p0

    .line 89
    invoke-virtual {p0}, Landroid/os/Parcel;->readStrongBinder()Landroid/os/IBinder;

    .line 90
    .line 91
    .line 92
    move-result-object p1

    .line 93
    if-nez p1, :cond_2

    .line 94
    .line 95
    goto :goto_1

    .line 96
    :cond_2
    const-string p3, "com.google.mlkit.vision.barcode.aidls.IBarcodeScanner"

    .line 97
    .line 98
    invoke-interface {p1, p3}, Landroid/os/IBinder;->queryLocalInterface(Ljava/lang/String;)Landroid/os/IInterface;

    .line 99
    .line 100
    .line 101
    move-result-object v0

    .line 102
    instance-of v1, v0, Ljp/nh;

    .line 103
    .line 104
    if-eqz v1, :cond_3

    .line 105
    .line 106
    move-object p3, v0

    .line 107
    check-cast p3, Ljp/nh;

    .line 108
    .line 109
    goto :goto_1

    .line 110
    :cond_3
    new-instance v0, Ljp/nh;

    .line 111
    .line 112
    invoke-direct {v0, p1, p3, p2}, Lbp/a;-><init>(Landroid/os/IBinder;Ljava/lang/String;I)V

    .line 113
    .line 114
    .line 115
    move-object p3, v0

    .line 116
    :goto_1
    invoke-virtual {p0}, Landroid/os/Parcel;->recycle()V

    .line 117
    .line 118
    .line 119
    return-object p3
.end method

.method public final j()Z
    .locals 10

    .line 1
    iget-object v0, p0, Llv/g;->g:Ljp/nh;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    iget-boolean p0, p0, Llv/g;->b:Z

    .line 6
    .line 7
    return p0

    .line 8
    :cond_0
    iget-object v1, p0, Llv/g;->d:Landroid/content/Context;

    .line 9
    .line 10
    const-string v0, "com.google.mlkit.dynamite.barcode"

    .line 11
    .line 12
    invoke-static {v1, v0}, Lzo/d;->a(Landroid/content/Context;Ljava/lang/String;)I

    .line 13
    .line 14
    .line 15
    move-result v2

    .line 16
    iget-object v6, p0, Llv/g;->f:Ljp/vg;

    .line 17
    .line 18
    const/4 v7, 0x1

    .line 19
    if-lez v2, :cond_1

    .line 20
    .line 21
    iput-boolean v7, p0, Llv/g;->b:Z

    .line 22
    .line 23
    :try_start_0
    sget-object v1, Lzo/d;->c:Lst/b;

    .line 24
    .line 25
    const-string v2, "com.google.mlkit.vision.barcode.bundled.internal.ThickBarcodeScannerCreator"

    .line 26
    .line 27
    invoke-virtual {p0, v1, v0, v2}, Llv/g;->b(Lzo/c;Ljava/lang/String;Ljava/lang/String;)Ljp/nh;

    .line 28
    .line 29
    .line 30
    move-result-object v0

    .line 31
    iput-object v0, p0, Llv/g;->g:Ljp/nh;
    :try_end_0
    .catch Lzo/a; {:try_start_0 .. :try_end_0} :catch_1
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 32
    .line 33
    goto/16 :goto_3

    .line 34
    .line 35
    :catch_0
    move-exception v0

    .line 36
    move-object p0, v0

    .line 37
    new-instance v0, Lbv/a;

    .line 38
    .line 39
    const-string v1, "Failed to create thick barcode scanner."

    .line 40
    .line 41
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 42
    .line 43
    .line 44
    throw v0

    .line 45
    :catch_1
    move-exception v0

    .line 46
    move-object p0, v0

    .line 47
    new-instance v0, Lbv/a;

    .line 48
    .line 49
    const-string v1, "Failed to load the bundled barcode module."

    .line 50
    .line 51
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 52
    .line 53
    .line 54
    throw v0

    .line 55
    :cond_1
    const/4 v8, 0x0

    .line 56
    iput-boolean v8, p0, Llv/g;->b:Z

    .line 57
    .line 58
    sget-object v0, Lfv/h;->a:[Ljo/d;

    .line 59
    .line 60
    sget-object v0, Ljo/f;->b:Ljo/f;

    .line 61
    .line 62
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 63
    .line 64
    .line 65
    invoke-static {v1}, Ljo/f;->a(Landroid/content/Context;)I

    .line 66
    .line 67
    .line 68
    move-result v0

    .line 69
    const v2, 0xd33d260

    .line 70
    .line 71
    .line 72
    sget-object v3, Llv/g;->h:Ljp/c0;

    .line 73
    .line 74
    if-lt v0, v2, :cond_2

    .line 75
    .line 76
    sget-object v0, Lfv/h;->e:Lip/l;

    .line 77
    .line 78
    invoke-static {v0, v3}, Lfv/h;->c(Lip/l;Ljava/util/List;)[Ljo/d;

    .line 79
    .line 80
    .line 81
    move-result-object v9

    .line 82
    :try_start_1
    new-instance v0, Lro/h;

    .line 83
    .line 84
    sget-object v3, Lro/h;->n:Lc2/k;

    .line 85
    .line 86
    sget-object v4, Lko/b;->a:Lko/a;

    .line 87
    .line 88
    sget-object v5, Lko/h;->c:Lko/h;

    .line 89
    .line 90
    const/4 v2, 0x0

    .line 91
    invoke-direct/range {v0 .. v5}, Lko/i;-><init>(Landroid/content/Context;Lcz/skodaauto/myskoda/app/main/system/MainActivity;Lc2/k;Lko/b;Lko/h;)V

    .line 92
    .line 93
    .line 94
    new-instance v2, Lfv/q;

    .line 95
    .line 96
    invoke-direct {v2, v9, v7}, Lfv/q;-><init>([Ljo/d;I)V

    .line 97
    .line 98
    .line 99
    new-array v3, v7, [Lko/m;

    .line 100
    .line 101
    aput-object v2, v3, v8

    .line 102
    .line 103
    invoke-virtual {v0, v3}, Lro/h;->f([Lko/m;)Laq/t;

    .line 104
    .line 105
    .line 106
    move-result-object v0

    .line 107
    new-instance v2, Lgv/a;

    .line 108
    .line 109
    const/4 v3, 0x5

    .line 110
    invoke-direct {v2, v3}, Lgv/a;-><init>(I)V

    .line 111
    .line 112
    .line 113
    invoke-virtual {v0}, Ljava/lang/Object;->getClass()Ljava/lang/Class;

    .line 114
    .line 115
    .line 116
    sget-object v3, Laq/l;->a:Lj0/e;

    .line 117
    .line 118
    invoke-virtual {v0, v3, v2}, Laq/t;->c(Ljava/util/concurrent/Executor;Laq/f;)Laq/t;

    .line 119
    .line 120
    .line 121
    invoke-static {v0}, Ljp/l1;->a(Laq/j;)Ljava/lang/Object;

    .line 122
    .line 123
    .line 124
    move-result-object v0

    .line 125
    check-cast v0, Lqo/a;

    .line 126
    .line 127
    iget-boolean v0, v0, Lqo/a;->d:Z
    :try_end_1
    .catch Ljava/util/concurrent/ExecutionException; {:try_start_1 .. :try_end_1} :catch_2
    .catch Ljava/lang/InterruptedException; {:try_start_1 .. :try_end_1} :catch_2

    .line 128
    .line 129
    goto :goto_1

    .line 130
    :catch_2
    move-exception v0

    .line 131
    const-string v2, "OptionalModuleUtils"

    .line 132
    .line 133
    const-string v3, "Failed to complete the task of features availability check"

    .line 134
    .line 135
    invoke-static {v2, v3, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 136
    .line 137
    .line 138
    :catch_3
    move v0, v8

    .line 139
    goto :goto_1

    .line 140
    :cond_2
    :try_start_2
    invoke-virtual {v3, v8}, Ljp/y;->m(I)Ljp/w;

    .line 141
    .line 142
    .line 143
    move-result-object v0

    .line 144
    :goto_0
    invoke-virtual {v0}, Ljp/w;->hasNext()Z

    .line 145
    .line 146
    .line 147
    move-result v2

    .line 148
    if-eqz v2, :cond_3

    .line 149
    .line 150
    invoke-virtual {v0}, Ljp/w;->next()Ljava/lang/Object;

    .line 151
    .line 152
    .line 153
    move-result-object v2

    .line 154
    check-cast v2, Ljava/lang/String;

    .line 155
    .line 156
    sget-object v3, Lzo/d;->b:Lrb0/a;

    .line 157
    .line 158
    invoke-static {v1, v3, v2}, Lzo/d;->c(Landroid/content/Context;Lzo/c;Ljava/lang/String;)Lzo/d;
    :try_end_2
    .catch Lzo/a; {:try_start_2 .. :try_end_2} :catch_3

    .line 159
    .line 160
    .line 161
    goto :goto_0

    .line 162
    :cond_3
    move v0, v7

    .line 163
    :goto_1
    if-nez v0, :cond_7

    .line 164
    .line 165
    iget-boolean v0, p0, Llv/g;->c:Z

    .line 166
    .line 167
    if-nez v0, :cond_6

    .line 168
    .line 169
    const-string v0, "barcode"

    .line 170
    .line 171
    const-string v2, "tflite_dynamite"

    .line 172
    .line 173
    filled-new-array {v0, v2}, [Ljava/lang/Object;

    .line 174
    .line 175
    .line 176
    move-result-object v0

    .line 177
    :goto_2
    const/4 v2, 0x2

    .line 178
    if-ge v8, v2, :cond_5

    .line 179
    .line 180
    aget-object v2, v0, v8

    .line 181
    .line 182
    if-eqz v2, :cond_4

    .line 183
    .line 184
    add-int/lit8 v8, v8, 0x1

    .line 185
    .line 186
    goto :goto_2

    .line 187
    :cond_4
    new-instance p0, Ljava/lang/NullPointerException;

    .line 188
    .line 189
    const-string v0, "at index "

    .line 190
    .line 191
    invoke-static {v8, v0}, Lkx/a;->h(ILjava/lang/String;)Ljava/lang/String;

    .line 192
    .line 193
    .line 194
    move-result-object v0

    .line 195
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 196
    .line 197
    .line 198
    throw p0

    .line 199
    :cond_5
    new-instance v3, Ljp/c0;

    .line 200
    .line 201
    invoke-direct {v3, v0, v2}, Ljp/c0;-><init>([Ljava/lang/Object;I)V

    .line 202
    .line 203
    .line 204
    invoke-static {v1, v3}, Lfv/h;->a(Landroid/content/Context;Ljava/util/List;)V

    .line 205
    .line 206
    .line 207
    iput-boolean v7, p0, Llv/g;->c:Z

    .line 208
    .line 209
    :cond_6
    sget-object p0, Ljp/ac;->g:Ljp/ac;

    .line 210
    .line 211
    invoke-static {v6, p0}, Llv/a;->b(Ljp/vg;Ljp/ac;)V

    .line 212
    .line 213
    .line 214
    new-instance p0, Lbv/a;

    .line 215
    .line 216
    const-string v0, "Waiting for the barcode module to be downloaded. Please wait."

    .line 217
    .line 218
    const/16 v1, 0xe

    .line 219
    .line 220
    invoke-direct {p0, v0, v1}, Lbv/a;-><init>(Ljava/lang/String;I)V

    .line 221
    .line 222
    .line 223
    throw p0

    .line 224
    :cond_7
    :try_start_3
    sget-object v0, Lzo/d;->b:Lrb0/a;

    .line 225
    .line 226
    const-string v1, "com.google.android.gms.vision.barcode"

    .line 227
    .line 228
    const-string v2, "com.google.android.gms.vision.barcode.mlkit.BarcodeScannerCreator"

    .line 229
    .line 230
    invoke-virtual {p0, v0, v1, v2}, Llv/g;->b(Lzo/c;Ljava/lang/String;Ljava/lang/String;)Ljp/nh;

    .line 231
    .line 232
    .line 233
    move-result-object v0

    .line 234
    iput-object v0, p0, Llv/g;->g:Ljp/nh;
    :try_end_3
    .catch Lzo/a; {:try_start_3 .. :try_end_3} :catch_4
    .catch Landroid/os/RemoteException; {:try_start_3 .. :try_end_3} :catch_4

    .line 235
    .line 236
    :goto_3
    sget-object v0, Ljp/ac;->e:Ljp/ac;

    .line 237
    .line 238
    invoke-static {v6, v0}, Llv/a;->b(Ljp/vg;Ljp/ac;)V

    .line 239
    .line 240
    .line 241
    iget-boolean p0, p0, Llv/g;->b:Z

    .line 242
    .line 243
    return p0

    .line 244
    :catch_4
    move-exception v0

    .line 245
    move-object p0, v0

    .line 246
    sget-object v0, Ljp/ac;->h:Ljp/ac;

    .line 247
    .line 248
    invoke-static {v6, v0}, Llv/a;->b(Ljp/vg;Ljp/ac;)V

    .line 249
    .line 250
    .line 251
    new-instance v0, Lbv/a;

    .line 252
    .line 253
    const-string v1, "Failed to create thin barcode scanner."

    .line 254
    .line 255
    invoke-direct {v0, v1, p0}, Lbv/a;-><init>(Ljava/lang/String;Ljava/lang/Exception;)V

    .line 256
    .line 257
    .line 258
    throw v0
.end method

.method public final l()V
    .locals 3

    .line 1
    iget-object v0, p0, Llv/g;->g:Ljp/nh;

    .line 2
    .line 3
    if-eqz v0, :cond_0

    .line 4
    .line 5
    :try_start_0
    invoke-virtual {v0}, Lbp/a;->S()Landroid/os/Parcel;

    .line 6
    .line 7
    .line 8
    move-result-object v1

    .line 9
    const/4 v2, 0x2

    .line 10
    invoke-virtual {v0, v1, v2}, Lbp/a;->U(Landroid/os/Parcel;I)V
    :try_end_0
    .catch Landroid/os/RemoteException; {:try_start_0 .. :try_end_0} :catch_0

    .line 11
    .line 12
    .line 13
    goto :goto_0

    .line 14
    :catch_0
    move-exception v0

    .line 15
    const-string v1, "DecoupledBarcodeScanner"

    .line 16
    .line 17
    const-string v2, "Failed to release barcode scanner."

    .line 18
    .line 19
    invoke-static {v1, v2, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 20
    .line 21
    .line 22
    :goto_0
    const/4 v0, 0x0

    .line 23
    iput-object v0, p0, Llv/g;->g:Ljp/nh;

    .line 24
    .line 25
    const/4 v0, 0x0

    .line 26
    iput-boolean v0, p0, Llv/g;->a:Z

    .line 27
    .line 28
    :cond_0
    return-void
.end method

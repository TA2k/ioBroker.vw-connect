.class public final Lcom/google/android/gms/common/data/DataHolder;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"

# interfaces
.implements Ljava/io/Closeable;


# annotations
.annotation build Lcom/google/android/gms/common/annotation/KeepName;
.end annotation


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lcom/google/android/gms/common/data/DataHolder;",
            ">;"
        }
    .end annotation
.end field

.field public static final n:Lb81/a;


# instance fields
.field public final d:I

.field public final e:[Ljava/lang/String;

.field public f:Landroid/os/Bundle;

.field public final g:[Landroid/database/CursorWindow;

.field public final h:I

.field public final i:Landroid/os/Bundle;

.field public j:[I

.field public k:I

.field public l:Z

.field public final m:Z


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Lkg/l0;

    .line 2
    .line 3
    const/4 v1, 0x6

    .line 4
    invoke-direct {v0, v1}, Lkg/l0;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lcom/google/android/gms/common/data/DataHolder;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    new-instance v0, Lb81/a;

    .line 10
    .line 11
    const/4 v1, 0x0

    .line 12
    new-array v1, v1, [Ljava/lang/String;

    .line 13
    .line 14
    invoke-direct {v0, v1}, Lb81/a;-><init>([Ljava/lang/String;)V

    .line 15
    .line 16
    .line 17
    sput-object v0, Lcom/google/android/gms/common/data/DataHolder;->n:Lb81/a;

    .line 18
    .line 19
    return-void
.end method

.method public constructor <init>(I[Ljava/lang/String;[Landroid/database/CursorWindow;ILandroid/os/Bundle;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    const/4 v0, 0x0

    .line 2
    iput-boolean v0, p0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    const/4 v0, 0x1

    iput-boolean v0, p0, Lcom/google/android/gms/common/data/DataHolder;->m:Z

    iput p1, p0, Lcom/google/android/gms/common/data/DataHolder;->d:I

    iput-object p2, p0, Lcom/google/android/gms/common/data/DataHolder;->e:[Ljava/lang/String;

    iput-object p3, p0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    iput p4, p0, Lcom/google/android/gms/common/data/DataHolder;->h:I

    iput-object p5, p0, Lcom/google/android/gms/common/data/DataHolder;->i:Landroid/os/Bundle;

    return-void
.end method

.method public constructor <init>(Lb81/a;I)V
    .locals 16

    move-object/from16 v0, p0

    move-object/from16 v1, p1

    .line 3
    iget-object v2, v1, Lb81/a;->e:Ljava/lang/Object;

    check-cast v2, [Ljava/lang/String;

    .line 4
    array-length v3, v2

    const/4 v4, 0x1

    const/4 v5, 0x0

    if-nez v3, :cond_0

    new-array v1, v5, [Landroid/database/CursorWindow;

    goto/16 :goto_7

    .line 5
    :cond_0
    iget-object v1, v1, Lb81/a;->f:Ljava/lang/Object;

    check-cast v1, Ljava/util/ArrayList;

    .line 6
    invoke-virtual {v1}, Ljava/util/ArrayList;->size()I

    move-result v3

    new-instance v6, Landroid/database/CursorWindow;

    .line 7
    invoke-direct {v6, v5}, Landroid/database/CursorWindow;-><init>(Z)V

    new-instance v7, Ljava/util/ArrayList;

    .line 8
    invoke-direct {v7}, Ljava/util/ArrayList;-><init>()V

    .line 9
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 10
    array-length v8, v2

    invoke-virtual {v6, v8}, Landroid/database/CursorWindow;->setNumColumns(I)Z

    move v8, v5

    move v9, v8

    :goto_0
    if-ge v8, v3, :cond_f

    .line 11
    :try_start_0
    invoke-virtual {v6}, Landroid/database/CursorWindow;->allocRow()Z

    move-result v10
    :try_end_0
    .catch Ljava/lang/RuntimeException; {:try_start_0 .. :try_end_0} :catch_0

    const-string v11, "DataHolder"

    if-nez v10, :cond_1

    :try_start_1
    new-instance v6, Ljava/lang/StringBuilder;

    .line 12
    invoke-direct {v6}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "Allocating additional cursor window for large data set (row "

    invoke-virtual {v6, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v10, ")"

    invoke-virtual {v6, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v6}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v6

    invoke-static {v11, v6}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    new-instance v6, Landroid/database/CursorWindow;

    .line 13
    invoke-direct {v6, v5}, Landroid/database/CursorWindow;-><init>(Z)V

    .line 14
    invoke-virtual {v6, v8}, Landroid/database/CursorWindow;->setStartPosition(I)V

    .line 15
    array-length v10, v2

    invoke-virtual {v6, v10}, Landroid/database/CursorWindow;->setNumColumns(I)Z

    .line 16
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 17
    invoke-virtual {v6}, Landroid/database/CursorWindow;->allocRow()Z

    move-result v10

    if-nez v10, :cond_1

    const-string v1, "Unable to allocate row to hold data."

    .line 18
    invoke-static {v11, v1}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I

    .line 19
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->remove(Ljava/lang/Object;)Z

    .line 20
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v1

    new-array v1, v1, [Landroid/database/CursorWindow;

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Landroid/database/CursorWindow;

    goto/16 :goto_7

    :catch_0
    move-exception v0

    goto/16 :goto_5

    .line 21
    :cond_1
    invoke-virtual {v1, v8}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v10

    check-cast v10, Ljava/util/Map;

    move v13, v4

    move v12, v5

    .line 22
    :goto_1
    array-length v14, v2

    if-ge v12, v14, :cond_b

    if-eqz v13, :cond_c

    .line 23
    aget-object v13, v2, v12

    .line 24
    invoke-interface {v10, v13}, Ljava/util/Map;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v14

    if-nez v14, :cond_2

    .line 25
    invoke-virtual {v6, v8, v12}, Landroid/database/CursorWindow;->putNull(II)Z

    move-result v13

    goto/16 :goto_3

    .line 26
    :cond_2
    instance-of v15, v14, Ljava/lang/String;

    if-eqz v15, :cond_3

    .line 27
    check-cast v14, Ljava/lang/String;

    invoke-virtual {v6, v14, v8, v12}, Landroid/database/CursorWindow;->putString(Ljava/lang/String;II)Z

    move-result v13

    goto :goto_3

    .line 28
    :cond_3
    instance-of v15, v14, Ljava/lang/Long;

    if-eqz v15, :cond_4

    .line 29
    check-cast v14, Ljava/lang/Long;

    invoke-virtual {v14}, Ljava/lang/Long;->longValue()J

    move-result-wide v13

    invoke-virtual {v6, v13, v14, v8, v12}, Landroid/database/CursorWindow;->putLong(JII)Z

    move-result v13

    goto :goto_3

    .line 30
    :cond_4
    instance-of v15, v14, Ljava/lang/Integer;

    if-eqz v15, :cond_5

    .line 31
    check-cast v14, Ljava/lang/Integer;

    invoke-virtual {v14}, Ljava/lang/Integer;->intValue()I

    move-result v13

    int-to-long v13, v13

    invoke-virtual {v6, v13, v14, v8, v12}, Landroid/database/CursorWindow;->putLong(JII)Z

    move-result v13

    goto :goto_3

    .line 32
    :cond_5
    instance-of v15, v14, Ljava/lang/Boolean;

    if-eqz v15, :cond_7

    .line 33
    check-cast v14, Ljava/lang/Boolean;

    invoke-virtual {v14}, Ljava/lang/Boolean;->booleanValue()Z

    move-result v13

    if-eq v4, v13, :cond_6

    const-wide/16 v13, 0x0

    goto :goto_2

    :cond_6
    const-wide/16 v13, 0x1

    .line 34
    :goto_2
    invoke-virtual {v6, v13, v14, v8, v12}, Landroid/database/CursorWindow;->putLong(JII)Z

    move-result v13

    goto :goto_3

    .line 35
    :cond_7
    instance-of v15, v14, [B

    if-eqz v15, :cond_8

    .line 36
    check-cast v14, [B

    invoke-virtual {v6, v14, v8, v12}, Landroid/database/CursorWindow;->putBlob([BII)Z

    move-result v13

    goto :goto_3

    .line 37
    :cond_8
    instance-of v15, v14, Ljava/lang/Double;

    if-eqz v15, :cond_9

    .line 38
    check-cast v14, Ljava/lang/Double;

    invoke-virtual {v14}, Ljava/lang/Double;->doubleValue()D

    move-result-wide v13

    invoke-virtual {v6, v13, v14, v8, v12}, Landroid/database/CursorWindow;->putDouble(DII)Z

    move-result v13

    goto :goto_3

    .line 39
    :cond_9
    instance-of v15, v14, Ljava/lang/Float;

    if-eqz v15, :cond_a

    .line 40
    check-cast v14, Ljava/lang/Float;

    invoke-virtual {v14}, Ljava/lang/Float;->floatValue()F

    move-result v13

    float-to-double v13, v13

    invoke-virtual {v6, v13, v14, v8, v12}, Landroid/database/CursorWindow;->putDouble(DII)Z

    move-result v13

    :goto_3
    add-int/lit8 v12, v12, 0x1

    goto :goto_1

    .line 41
    :cond_a
    new-instance v0, Ljava/lang/IllegalArgumentException;

    .line 42
    invoke-virtual {v14}, Ljava/lang/Object;->toString()Ljava/lang/String;

    move-result-object v1

    new-instance v2, Ljava/lang/StringBuilder;

    invoke-direct {v2}, Ljava/lang/StringBuilder;-><init>()V

    const-string v3, "Unsupported object for column "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v13}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    const-string v3, ": "

    invoke-virtual {v2, v3}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v2}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v1

    invoke-direct {v0, v1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    throw v0

    :cond_b
    if-eqz v13, :cond_c

    move v9, v5

    goto :goto_4

    :cond_c
    if-nez v9, :cond_d

    .line 43
    new-instance v9, Ljava/lang/StringBuilder;

    .line 44
    invoke-direct {v9}, Ljava/lang/StringBuilder;-><init>()V

    const-string v10, "Couldn\'t populate window data for row "

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9, v8}, Ljava/lang/StringBuilder;->append(I)Ljava/lang/StringBuilder;

    const-string v10, " - allocating new window."

    invoke-virtual {v9, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    invoke-virtual {v9}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    move-result-object v9

    invoke-static {v11, v9}, Landroid/util/Log;->d(Ljava/lang/String;Ljava/lang/String;)I

    .line 45
    invoke-virtual {v6}, Landroid/database/CursorWindow;->freeLastRow()V

    new-instance v6, Landroid/database/CursorWindow;

    .line 46
    invoke-direct {v6, v5}, Landroid/database/CursorWindow;-><init>(Z)V

    .line 47
    invoke-virtual {v6, v8}, Landroid/database/CursorWindow;->setStartPosition(I)V

    .line 48
    array-length v9, v2

    invoke-virtual {v6, v9}, Landroid/database/CursorWindow;->setNumColumns(I)Z

    .line 49
    invoke-virtual {v7, v6}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    add-int/lit8 v8, v8, -0x1

    move v9, v4

    :goto_4
    add-int/2addr v8, v4

    goto/16 :goto_0

    .line 50
    :cond_d
    new-instance v0, La8/r0;

    .line 51
    const-string v1, "Could not add the value to a new CursorWindow. The size of value may be larger than what a CursorWindow can handle."

    invoke-direct {v0, v1}, Ljava/lang/RuntimeException;-><init>(Ljava/lang/String;)V

    .line 52
    throw v0
    :try_end_1
    .catch Ljava/lang/RuntimeException; {:try_start_1 .. :try_end_1} :catch_0

    .line 53
    :goto_5
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v1

    :goto_6
    if-ge v5, v1, :cond_e

    .line 54
    invoke-virtual {v7, v5}, Ljava/util/ArrayList;->get(I)Ljava/lang/Object;

    move-result-object v2

    check-cast v2, Landroid/database/CursorWindow;

    invoke-virtual {v2}, Landroid/database/sqlite/SQLiteClosable;->close()V

    add-int/lit8 v5, v5, 0x1

    goto :goto_6

    .line 55
    :cond_e
    throw v0

    .line 56
    :cond_f
    invoke-virtual {v7}, Ljava/util/ArrayList;->size()I

    move-result v1

    new-array v1, v1, [Landroid/database/CursorWindow;

    invoke-virtual {v7, v1}, Ljava/util/ArrayList;->toArray([Ljava/lang/Object;)[Ljava/lang/Object;

    move-result-object v1

    check-cast v1, [Landroid/database/CursorWindow;

    .line 57
    :goto_7
    invoke-direct {v0}, Ljava/lang/Object;-><init>()V

    .line 58
    iput-boolean v5, v0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    iput-boolean v4, v0, Lcom/google/android/gms/common/data/DataHolder;->m:Z

    iput v4, v0, Lcom/google/android/gms/common/data/DataHolder;->d:I

    .line 59
    iput-object v2, v0, Lcom/google/android/gms/common/data/DataHolder;->e:[Ljava/lang/String;

    .line 60
    invoke-static {v1}, Lno/c0;->h(Ljava/lang/Object;)V

    iput-object v1, v0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    move/from16 v1, p2

    iput v1, v0, Lcom/google/android/gms/common/data/DataHolder;->h:I

    const/4 v1, 0x0

    iput-object v1, v0, Lcom/google/android/gms/common/data/DataHolder;->i:Landroid/os/Bundle;

    .line 61
    invoke-virtual {v0}, Lcom/google/android/gms/common/data/DataHolder;->y0()V

    return-void
.end method


# virtual methods
.method public final close()V
    .locals 3

    .line 1
    monitor-enter p0

    .line 2
    :try_start_0
    iget-boolean v0, p0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    .line 3
    .line 4
    if-nez v0, :cond_0

    .line 5
    .line 6
    const/4 v0, 0x1

    .line 7
    iput-boolean v0, p0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    .line 8
    .line 9
    const/4 v0, 0x0

    .line 10
    :goto_0
    iget-object v1, p0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 11
    .line 12
    array-length v2, v1

    .line 13
    if-ge v0, v2, :cond_0

    .line 14
    .line 15
    aget-object v1, v1, v0

    .line 16
    .line 17
    invoke-virtual {v1}, Landroid/database/sqlite/SQLiteClosable;->close()V

    .line 18
    .line 19
    .line 20
    add-int/lit8 v0, v0, 0x1

    .line 21
    .line 22
    goto :goto_0

    .line 23
    :catchall_0
    move-exception v0

    .line 24
    goto :goto_1

    .line 25
    :cond_0
    monitor-exit p0

    .line 26
    return-void

    .line 27
    :goto_1
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 28
    throw v0
.end method

.method public final finalize()V
    .locals 4

    .line 1
    const-string v0, "Internal data leak within a DataBuffer object detected!  Be sure to explicitly call release() on all DataBuffer extending objects when you are done with them. (internal object: "

    .line 2
    .line 3
    :try_start_0
    iget-boolean v1, p0, Lcom/google/android/gms/common/data/DataHolder;->m:Z

    .line 4
    .line 5
    if-eqz v1, :cond_0

    .line 6
    .line 7
    iget-object v1, p0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 8
    .line 9
    array-length v1, v1

    .line 10
    if-lez v1, :cond_0

    .line 11
    .line 12
    monitor-enter p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 13
    :try_start_1
    iget-boolean v1, p0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    .line 14
    .line 15
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_1

    .line 16
    if-nez v1, :cond_0

    .line 17
    .line 18
    :try_start_2
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 19
    .line 20
    .line 21
    const-string v1, "DataBuffer"

    .line 22
    .line 23
    invoke-virtual {p0}, Ljava/lang/Object;->toString()Ljava/lang/String;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    new-instance v3, Ljava/lang/StringBuilder;

    .line 28
    .line 29
    invoke-direct {v3, v0}, Ljava/lang/StringBuilder;-><init>(Ljava/lang/String;)V

    .line 30
    .line 31
    .line 32
    invoke-virtual {v3, v2}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 33
    .line 34
    .line 35
    const-string v0, ")"

    .line 36
    .line 37
    invoke-virtual {v3, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 38
    .line 39
    .line 40
    invoke-virtual {v3}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 41
    .line 42
    .line 43
    move-result-object v0

    .line 44
    invoke-static {v1, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;)I
    :try_end_2
    .catchall {:try_start_2 .. :try_end_2} :catchall_0

    .line 45
    .line 46
    .line 47
    goto :goto_0

    .line 48
    :catchall_0
    move-exception v0

    .line 49
    goto :goto_1

    .line 50
    :catchall_1
    move-exception v0

    .line 51
    :try_start_3
    monitor-exit p0
    :try_end_3
    .catchall {:try_start_3 .. :try_end_3} :catchall_1

    .line 52
    :try_start_4
    throw v0
    :try_end_4
    .catchall {:try_start_4 .. :try_end_4} :catchall_0

    .line 53
    :cond_0
    :goto_0
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 54
    .line 55
    .line 56
    return-void

    .line 57
    :goto_1
    invoke-super {p0}, Ljava/lang/Object;->finalize()V

    .line 58
    .line 59
    .line 60
    throw v0
.end method

.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 4

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
    const/4 v1, 0x1

    .line 8
    iget-object v2, p0, Lcom/google/android/gms/common/data/DataHolder;->e:[Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1, v1, v2}, Ljp/dc;->o(Landroid/os/Parcel;I[Ljava/lang/String;)V

    .line 11
    .line 12
    .line 13
    const/4 v2, 0x2

    .line 14
    iget-object v3, p0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 15
    .line 16
    invoke-static {p1, v2, v3, p2}, Ljp/dc;->q(Landroid/os/Parcel;I[Landroid/os/Parcelable;I)V

    .line 17
    .line 18
    .line 19
    const/4 v2, 0x3

    .line 20
    const/4 v3, 0x4

    .line 21
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 22
    .line 23
    .line 24
    iget v2, p0, Lcom/google/android/gms/common/data/DataHolder;->h:I

    .line 25
    .line 26
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 27
    .line 28
    .line 29
    iget-object v2, p0, Lcom/google/android/gms/common/data/DataHolder;->i:Landroid/os/Bundle;

    .line 30
    .line 31
    invoke-static {p1, v3, v2}, Ljp/dc;->f(Landroid/os/Parcel;ILandroid/os/Bundle;)V

    .line 32
    .line 33
    .line 34
    const/16 v2, 0x3e8

    .line 35
    .line 36
    invoke-static {p1, v2, v3}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 37
    .line 38
    .line 39
    iget v2, p0, Lcom/google/android/gms/common/data/DataHolder;->d:I

    .line 40
    .line 41
    invoke-virtual {p1, v2}, Landroid/os/Parcel;->writeInt(I)V

    .line 42
    .line 43
    .line 44
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 45
    .line 46
    .line 47
    and-int/lit8 p1, p2, 0x1

    .line 48
    .line 49
    if-eqz p1, :cond_0

    .line 50
    .line 51
    invoke-virtual {p0}, Lcom/google/android/gms/common/data/DataHolder;->close()V

    .line 52
    .line 53
    .line 54
    :cond_0
    return-void
.end method

.method public final x0(I)I
    .locals 3

    .line 1
    const/4 v0, 0x0

    .line 2
    if-ltz p1, :cond_0

    .line 3
    .line 4
    iget v1, p0, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 5
    .line 6
    if-ge p1, v1, :cond_0

    .line 7
    .line 8
    const/4 v1, 0x1

    .line 9
    goto :goto_0

    .line 10
    :cond_0
    move v1, v0

    .line 11
    :goto_0
    invoke-static {v1}, Lno/c0;->k(Z)V

    .line 12
    .line 13
    .line 14
    :goto_1
    iget-object v1, p0, Lcom/google/android/gms/common/data/DataHolder;->j:[I

    .line 15
    .line 16
    array-length v2, v1

    .line 17
    if-ge v0, v2, :cond_2

    .line 18
    .line 19
    aget v1, v1, v0

    .line 20
    .line 21
    if-ge p1, v1, :cond_1

    .line 22
    .line 23
    add-int/lit8 v0, v0, -0x1

    .line 24
    .line 25
    goto :goto_2

    .line 26
    :cond_1
    add-int/lit8 v0, v0, 0x1

    .line 27
    .line 28
    goto :goto_1

    .line 29
    :cond_2
    :goto_2
    if-ne v0, v2, :cond_3

    .line 30
    .line 31
    add-int/lit8 v0, v0, -0x1

    .line 32
    .line 33
    :cond_3
    return v0
.end method

.method public final y0()V
    .locals 5

    .line 1
    new-instance v0, Landroid/os/Bundle;

    .line 2
    .line 3
    invoke-direct {v0}, Landroid/os/Bundle;-><init>()V

    .line 4
    .line 5
    .line 6
    iput-object v0, p0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 7
    .line 8
    const/4 v0, 0x0

    .line 9
    move v1, v0

    .line 10
    :goto_0
    iget-object v2, p0, Lcom/google/android/gms/common/data/DataHolder;->e:[Ljava/lang/String;

    .line 11
    .line 12
    array-length v3, v2

    .line 13
    if-ge v1, v3, :cond_0

    .line 14
    .line 15
    iget-object v3, p0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 16
    .line 17
    aget-object v2, v2, v1

    .line 18
    .line 19
    invoke-virtual {v3, v2, v1}, Landroid/os/BaseBundle;->putInt(Ljava/lang/String;I)V

    .line 20
    .line 21
    .line 22
    add-int/lit8 v1, v1, 0x1

    .line 23
    .line 24
    goto :goto_0

    .line 25
    :cond_0
    iget-object v1, p0, Lcom/google/android/gms/common/data/DataHolder;->g:[Landroid/database/CursorWindow;

    .line 26
    .line 27
    array-length v2, v1

    .line 28
    new-array v2, v2, [I

    .line 29
    .line 30
    iput-object v2, p0, Lcom/google/android/gms/common/data/DataHolder;->j:[I

    .line 31
    .line 32
    move v2, v0

    .line 33
    :goto_1
    array-length v3, v1

    .line 34
    if-ge v0, v3, :cond_1

    .line 35
    .line 36
    iget-object v3, p0, Lcom/google/android/gms/common/data/DataHolder;->j:[I

    .line 37
    .line 38
    aput v2, v3, v0

    .line 39
    .line 40
    aget-object v3, v1, v0

    .line 41
    .line 42
    invoke-virtual {v3}, Landroid/database/CursorWindow;->getStartPosition()I

    .line 43
    .line 44
    .line 45
    move-result v3

    .line 46
    sub-int v3, v2, v3

    .line 47
    .line 48
    aget-object v4, v1, v0

    .line 49
    .line 50
    invoke-virtual {v4}, Landroid/database/CursorWindow;->getNumRows()I

    .line 51
    .line 52
    .line 53
    move-result v4

    .line 54
    sub-int/2addr v4, v3

    .line 55
    add-int/2addr v2, v4

    .line 56
    add-int/lit8 v0, v0, 0x1

    .line 57
    .line 58
    goto :goto_1

    .line 59
    :cond_1
    iput v2, p0, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 60
    .line 61
    return-void
.end method

.method public final z0(ILjava/lang/String;)V
    .locals 1

    .line 1
    iget-object v0, p0, Lcom/google/android/gms/common/data/DataHolder;->f:Landroid/os/Bundle;

    .line 2
    .line 3
    if-eqz v0, :cond_2

    .line 4
    .line 5
    invoke-virtual {v0, p2}, Landroid/os/BaseBundle;->containsKey(Ljava/lang/String;)Z

    .line 6
    .line 7
    .line 8
    move-result v0

    .line 9
    if-eqz v0, :cond_2

    .line 10
    .line 11
    monitor-enter p0

    .line 12
    :try_start_0
    iget-boolean p2, p0, Lcom/google/android/gms/common/data/DataHolder;->l:Z

    .line 13
    .line 14
    monitor-exit p0
    :try_end_0
    .catchall {:try_start_0 .. :try_end_0} :catchall_0

    .line 15
    if-nez p2, :cond_1

    .line 16
    .line 17
    if-ltz p1, :cond_0

    .line 18
    .line 19
    iget p2, p0, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 20
    .line 21
    if-ge p1, p2, :cond_0

    .line 22
    .line 23
    return-void

    .line 24
    :cond_0
    new-instance p2, Landroid/database/CursorIndexOutOfBoundsException;

    .line 25
    .line 26
    iget p0, p0, Lcom/google/android/gms/common/data/DataHolder;->k:I

    .line 27
    .line 28
    invoke-direct {p2, p1, p0}, Landroid/database/CursorIndexOutOfBoundsException;-><init>(II)V

    .line 29
    .line 30
    .line 31
    throw p2

    .line 32
    :cond_1
    new-instance p0, Ljava/lang/IllegalArgumentException;

    .line 33
    .line 34
    const-string p1, "Buffer is closed."

    .line 35
    .line 36
    invoke-direct {p0, p1}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 37
    .line 38
    .line 39
    throw p0

    .line 40
    :catchall_0
    move-exception p1

    .line 41
    :try_start_1
    monitor-exit p0
    :try_end_1
    .catchall {:try_start_1 .. :try_end_1} :catchall_0

    .line 42
    throw p1

    .line 43
    :cond_2
    invoke-static {p2}, Ljava/lang/String;->valueOf(Ljava/lang/Object;)Ljava/lang/String;

    .line 44
    .line 45
    .line 46
    move-result-object p0

    .line 47
    const-string p1, "No such column: "

    .line 48
    .line 49
    new-instance p2, Ljava/lang/IllegalArgumentException;

    .line 50
    .line 51
    invoke-virtual {p1, p0}, Ljava/lang/String;->concat(Ljava/lang/String;)Ljava/lang/String;

    .line 52
    .line 53
    .line 54
    move-result-object p0

    .line 55
    invoke-direct {p2, p0}, Ljava/lang/IllegalArgumentException;-><init>(Ljava/lang/String;)V

    .line 56
    .line 57
    .line 58
    throw p2
.end method

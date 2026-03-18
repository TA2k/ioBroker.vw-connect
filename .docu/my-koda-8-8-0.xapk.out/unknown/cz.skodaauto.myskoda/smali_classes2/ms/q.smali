.class public final Lms/q;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final f:Ljava/util/HashMap;

.field public static final g:Ljava/lang/String;


# instance fields
.field public final a:Landroid/content/Context;

.field public final b:Lms/u;

.field public final c:Lcom/google/android/material/datepicker/d;

.field public final d:Lvp/y1;

.field public final e:Lqn/s;


# direct methods
.method static constructor <clinit>()V
    .locals 5

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/HashMap;-><init>()V

    .line 4
    .line 5
    .line 6
    sput-object v0, Lms/q;->f:Ljava/util/HashMap;

    .line 7
    .line 8
    const-string v1, "armeabi-v7a"

    .line 9
    .line 10
    const/4 v2, 0x6

    .line 11
    const/4 v3, 0x5

    .line 12
    const-string v4, "armeabi"

    .line 13
    .line 14
    invoke-static {v3, v0, v4, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 15
    .line 16
    .line 17
    const-string v1, "x86"

    .line 18
    .line 19
    const/4 v2, 0x0

    .line 20
    const/16 v3, 0x9

    .line 21
    .line 22
    const-string v4, "arm64-v8a"

    .line 23
    .line 24
    invoke-static {v3, v0, v4, v2, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 25
    .line 26
    .line 27
    const/4 v1, 0x1

    .line 28
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 29
    .line 30
    .line 31
    move-result-object v1

    .line 32
    const-string v2, "x86_64"

    .line 33
    .line 34
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 35
    .line 36
    .line 37
    sget-object v0, Ljava/util/Locale;->US:Ljava/util/Locale;

    .line 38
    .line 39
    const-string v0, "Crashlytics Android SDK/20.0.3"

    .line 40
    .line 41
    sput-object v0, Lms/q;->g:Ljava/lang/String;

    .line 42
    .line 43
    return-void
.end method

.method public constructor <init>(Landroid/content/Context;Lms/u;Lcom/google/android/material/datepicker/d;Lvp/y1;Lqn/s;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    iput-object p1, p0, Lms/q;->a:Landroid/content/Context;

    .line 5
    .line 6
    iput-object p2, p0, Lms/q;->b:Lms/u;

    .line 7
    .line 8
    iput-object p3, p0, Lms/q;->c:Lcom/google/android/material/datepicker/d;

    .line 9
    .line 10
    iput-object p4, p0, Lms/q;->d:Lvp/y1;

    .line 11
    .line 12
    iput-object p5, p0, Lms/q;->e:Lqn/s;

    .line 13
    .line 14
    return-void
.end method

.method public static c(Lun/a;I)Lps/t0;
    .locals 7

    .line 1
    iget-object v0, p0, Lun/a;->e:Ljava/lang/Object;

    .line 2
    .line 3
    move-object v2, v0

    .line 4
    check-cast v2, Ljava/lang/String;

    .line 5
    .line 6
    iget-object v0, p0, Lun/a;->h:Ljava/lang/Object;

    .line 7
    .line 8
    move-object v3, v0

    .line 9
    check-cast v3, Ljava/lang/String;

    .line 10
    .line 11
    iget-object v0, p0, Lun/a;->f:Ljava/lang/Object;

    .line 12
    .line 13
    check-cast v0, [Ljava/lang/StackTraceElement;

    .line 14
    .line 15
    const/4 v1, 0x0

    .line 16
    if-eqz v0, :cond_0

    .line 17
    .line 18
    goto :goto_0

    .line 19
    :cond_0
    new-array v0, v1, [Ljava/lang/StackTraceElement;

    .line 20
    .line 21
    :goto_0
    iget-object p0, p0, Lun/a;->g:Ljava/lang/Object;

    .line 22
    .line 23
    check-cast p0, Lun/a;

    .line 24
    .line 25
    const/16 v4, 0x8

    .line 26
    .line 27
    if-lt p1, v4, :cond_1

    .line 28
    .line 29
    move-object v4, p0

    .line 30
    :goto_1
    if-eqz v4, :cond_1

    .line 31
    .line 32
    iget-object v4, v4, Lun/a;->g:Ljava/lang/Object;

    .line 33
    .line 34
    check-cast v4, Lun/a;

    .line 35
    .line 36
    add-int/lit8 v1, v1, 0x1

    .line 37
    .line 38
    goto :goto_1

    .line 39
    :cond_1
    move v6, v1

    .line 40
    const/4 v1, 0x4

    .line 41
    invoke-static {v0, v1}, Lms/q;->d([Ljava/lang/StackTraceElement;I)Ljava/util/List;

    .line 42
    .line 43
    .line 44
    move-result-object v4

    .line 45
    if-eqz v4, :cond_5

    .line 46
    .line 47
    const/4 v0, 0x0

    .line 48
    const/4 v1, 0x1

    .line 49
    or-int/2addr v0, v1

    .line 50
    int-to-byte v0, v0

    .line 51
    const/4 v5, 0x0

    .line 52
    if-eqz p0, :cond_2

    .line 53
    .line 54
    if-nez v6, :cond_2

    .line 55
    .line 56
    add-int/2addr p1, v1

    .line 57
    invoke-static {p0, p1}, Lms/q;->c(Lun/a;I)Lps/t0;

    .line 58
    .line 59
    .line 60
    move-result-object v5

    .line 61
    :cond_2
    if-ne v0, v1, :cond_3

    .line 62
    .line 63
    new-instance v1, Lps/t0;

    .line 64
    .line 65
    invoke-direct/range {v1 .. v6}, Lps/t0;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/util/List;Lps/x1;I)V

    .line 66
    .line 67
    .line 68
    return-object v1

    .line 69
    :cond_3
    new-instance p0, Ljava/lang/StringBuilder;

    .line 70
    .line 71
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 72
    .line 73
    .line 74
    and-int/lit8 p1, v0, 0x1

    .line 75
    .line 76
    if-nez p1, :cond_4

    .line 77
    .line 78
    const-string p1, " overflowCount"

    .line 79
    .line 80
    invoke-virtual {p0, p1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 81
    .line 82
    .line 83
    :cond_4
    new-instance p1, Ljava/lang/IllegalStateException;

    .line 84
    .line 85
    const-string v0, "Missing required properties:"

    .line 86
    .line 87
    invoke-static {v0, p0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 88
    .line 89
    .line 90
    move-result-object p0

    .line 91
    invoke-direct {p1, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 92
    .line 93
    .line 94
    throw p1

    .line 95
    :cond_5
    new-instance p0, Ljava/lang/NullPointerException;

    .line 96
    .line 97
    const-string p1, "Null frames"

    .line 98
    .line 99
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 100
    .line 101
    .line 102
    throw p0
.end method

.method public static d([Ljava/lang/StackTraceElement;I)Ljava/util/List;
    .locals 12

    .line 1
    new-instance v0, Ljava/util/ArrayList;

    .line 2
    .line 3
    invoke-direct {v0}, Ljava/util/ArrayList;-><init>()V

    .line 4
    .line 5
    .line 6
    array-length v1, p0

    .line 7
    const/4 v2, 0x0

    .line 8
    :goto_0
    if-ge v2, v1, :cond_3

    .line 9
    .line 10
    aget-object v3, p0, v2

    .line 11
    .line 12
    new-instance v4, Lps/w0;

    .line 13
    .line 14
    invoke-direct {v4}, Ljava/lang/Object;-><init>()V

    .line 15
    .line 16
    .line 17
    iput p1, v4, Lps/w0;->e:I

    .line 18
    .line 19
    iget-byte v5, v4, Lps/w0;->f:B

    .line 20
    .line 21
    or-int/lit8 v5, v5, 0x4

    .line 22
    .line 23
    int-to-byte v5, v5

    .line 24
    iput-byte v5, v4, Lps/w0;->f:B

    .line 25
    .line 26
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->isNativeMethod()Z

    .line 27
    .line 28
    .line 29
    move-result v5

    .line 30
    const-wide/16 v6, 0x0

    .line 31
    .line 32
    if-eqz v5, :cond_0

    .line 33
    .line 34
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getLineNumber()I

    .line 35
    .line 36
    .line 37
    move-result v5

    .line 38
    int-to-long v8, v5

    .line 39
    invoke-static {v8, v9, v6, v7}, Ljava/lang/Math;->max(JJ)J

    .line 40
    .line 41
    .line 42
    move-result-wide v8

    .line 43
    goto :goto_1

    .line 44
    :cond_0
    move-wide v8, v6

    .line 45
    :goto_1
    new-instance v5, Ljava/lang/StringBuilder;

    .line 46
    .line 47
    invoke-direct {v5}, Ljava/lang/StringBuilder;-><init>()V

    .line 48
    .line 49
    .line 50
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getClassName()Ljava/lang/String;

    .line 51
    .line 52
    .line 53
    move-result-object v10

    .line 54
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 55
    .line 56
    .line 57
    const-string v10, "."

    .line 58
    .line 59
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 60
    .line 61
    .line 62
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getMethodName()Ljava/lang/String;

    .line 63
    .line 64
    .line 65
    move-result-object v10

    .line 66
    invoke-virtual {v5, v10}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 67
    .line 68
    .line 69
    invoke-virtual {v5}, Ljava/lang/StringBuilder;->toString()Ljava/lang/String;

    .line 70
    .line 71
    .line 72
    move-result-object v5

    .line 73
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getFileName()Ljava/lang/String;

    .line 74
    .line 75
    .line 76
    move-result-object v10

    .line 77
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->isNativeMethod()Z

    .line 78
    .line 79
    .line 80
    move-result v11

    .line 81
    if-nez v11, :cond_1

    .line 82
    .line 83
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getLineNumber()I

    .line 84
    .line 85
    .line 86
    move-result v11

    .line 87
    if-lez v11, :cond_1

    .line 88
    .line 89
    invoke-virtual {v3}, Ljava/lang/StackTraceElement;->getLineNumber()I

    .line 90
    .line 91
    .line 92
    move-result v3

    .line 93
    int-to-long v6, v3

    .line 94
    :cond_1
    iput-wide v8, v4, Lps/w0;->a:J

    .line 95
    .line 96
    iget-byte v3, v4, Lps/w0;->f:B

    .line 97
    .line 98
    or-int/lit8 v3, v3, 0x1

    .line 99
    .line 100
    int-to-byte v3, v3

    .line 101
    iput-byte v3, v4, Lps/w0;->f:B

    .line 102
    .line 103
    if-eqz v5, :cond_2

    .line 104
    .line 105
    iput-object v5, v4, Lps/w0;->b:Ljava/lang/String;

    .line 106
    .line 107
    iput-object v10, v4, Lps/w0;->c:Ljava/lang/String;

    .line 108
    .line 109
    iput-wide v6, v4, Lps/w0;->d:J

    .line 110
    .line 111
    or-int/lit8 v3, v3, 0x2

    .line 112
    .line 113
    int-to-byte v3, v3

    .line 114
    iput-byte v3, v4, Lps/w0;->f:B

    .line 115
    .line 116
    invoke-virtual {v4}, Lps/w0;->a()Lps/x0;

    .line 117
    .line 118
    .line 119
    move-result-object v3

    .line 120
    invoke-virtual {v0, v3}, Ljava/util/ArrayList;->add(Ljava/lang/Object;)Z

    .line 121
    .line 122
    .line 123
    add-int/lit8 v2, v2, 0x1

    .line 124
    .line 125
    goto :goto_0

    .line 126
    :cond_2
    new-instance p0, Ljava/lang/NullPointerException;

    .line 127
    .line 128
    const-string p1, "Null symbol"

    .line 129
    .line 130
    invoke-direct {p0, p1}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 131
    .line 132
    .line 133
    throw p0

    .line 134
    :cond_3
    invoke-static {v0}, Ljava/util/Collections;->unmodifiableList(Ljava/util/List;)Ljava/util/List;

    .line 135
    .line 136
    .line 137
    move-result-object p0

    .line 138
    return-object p0
.end method

.method public static e()Lps/u0;
    .locals 4

    .line 1
    const/4 v0, 0x1

    .line 2
    int-to-byte v1, v0

    .line 3
    if-ne v1, v0, :cond_0

    .line 4
    .line 5
    new-instance v0, Lps/u0;

    .line 6
    .line 7
    const-wide/16 v1, 0x0

    .line 8
    .line 9
    const-string v3, "0"

    .line 10
    .line 11
    invoke-direct {v0, v1, v2, v3, v3}, Lps/u0;-><init>(JLjava/lang/String;Ljava/lang/String;)V

    .line 12
    .line 13
    .line 14
    return-object v0

    .line 15
    :cond_0
    new-instance v0, Ljava/lang/StringBuilder;

    .line 16
    .line 17
    invoke-direct {v0}, Ljava/lang/StringBuilder;-><init>()V

    .line 18
    .line 19
    .line 20
    if-nez v1, :cond_1

    .line 21
    .line 22
    const-string v1, " address"

    .line 23
    .line 24
    invoke-virtual {v0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 25
    .line 26
    .line 27
    :cond_1
    new-instance v1, Ljava/lang/IllegalStateException;

    .line 28
    .line 29
    const-string v2, "Missing required properties:"

    .line 30
    .line 31
    invoke-static {v2, v0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 32
    .line 33
    .line 34
    move-result-object v0

    .line 35
    invoke-direct {v1, v0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 36
    .line 37
    .line 38
    throw v1
.end method


# virtual methods
.method public final a()Ljava/util/List;
    .locals 9

    .line 1
    const/4 v0, 0x0

    .line 2
    or-int/lit8 v0, v0, 0x1

    .line 3
    .line 4
    int-to-byte v0, v0

    .line 5
    or-int/lit8 v0, v0, 0x2

    .line 6
    .line 7
    int-to-byte v0, v0

    .line 8
    iget-object p0, p0, Lms/q;->c:Lcom/google/android/material/datepicker/d;

    .line 9
    .line 10
    iget-object v1, p0, Lcom/google/android/material/datepicker/d;->e:Ljava/lang/Object;

    .line 11
    .line 12
    move-object v7, v1

    .line 13
    check-cast v7, Ljava/lang/String;

    .line 14
    .line 15
    if-eqz v7, :cond_3

    .line 16
    .line 17
    iget-object p0, p0, Lcom/google/android/material/datepicker/d;->b:Ljava/lang/Object;

    .line 18
    .line 19
    move-object v8, p0

    .line 20
    check-cast v8, Ljava/lang/String;

    .line 21
    .line 22
    const/4 p0, 0x3

    .line 23
    if-ne v0, p0, :cond_0

    .line 24
    .line 25
    new-instance v2, Lps/s0;

    .line 26
    .line 27
    const-wide/16 v3, 0x0

    .line 28
    .line 29
    move-wide v5, v3

    .line 30
    invoke-direct/range {v2 .. v8}, Lps/s0;-><init>(JJLjava/lang/String;Ljava/lang/String;)V

    .line 31
    .line 32
    .line 33
    invoke-static {v2}, Ljava/util/Collections;->singletonList(Ljava/lang/Object;)Ljava/util/List;

    .line 34
    .line 35
    .line 36
    move-result-object p0

    .line 37
    return-object p0

    .line 38
    :cond_0
    new-instance p0, Ljava/lang/StringBuilder;

    .line 39
    .line 40
    invoke-direct {p0}, Ljava/lang/StringBuilder;-><init>()V

    .line 41
    .line 42
    .line 43
    and-int/lit8 v1, v0, 0x1

    .line 44
    .line 45
    if-nez v1, :cond_1

    .line 46
    .line 47
    const-string v1, " baseAddress"

    .line 48
    .line 49
    invoke-virtual {p0, v1}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 50
    .line 51
    .line 52
    :cond_1
    and-int/lit8 v0, v0, 0x2

    .line 53
    .line 54
    if-nez v0, :cond_2

    .line 55
    .line 56
    const-string v0, " size"

    .line 57
    .line 58
    invoke-virtual {p0, v0}, Ljava/lang/StringBuilder;->append(Ljava/lang/String;)Ljava/lang/StringBuilder;

    .line 59
    .line 60
    .line 61
    :cond_2
    new-instance v0, Ljava/lang/IllegalStateException;

    .line 62
    .line 63
    const-string v1, "Missing required properties:"

    .line 64
    .line 65
    invoke-static {v1, p0}, Lkx/a;->j(Ljava/lang/String;Ljava/lang/StringBuilder;)Ljava/lang/String;

    .line 66
    .line 67
    .line 68
    move-result-object p0

    .line 69
    invoke-direct {v0, p0}, Ljava/lang/IllegalStateException;-><init>(Ljava/lang/String;)V

    .line 70
    .line 71
    .line 72
    throw v0

    .line 73
    :cond_3
    new-instance p0, Ljava/lang/NullPointerException;

    .line 74
    .line 75
    const-string v0, "Null name"

    .line 76
    .line 77
    invoke-direct {p0, v0}, Ljava/lang/NullPointerException;-><init>(Ljava/lang/String;)V

    .line 78
    .line 79
    .line 80
    throw p0
.end method

.method public final b(I)Lps/b1;
    .locals 16

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    iget-object v1, v0, Lms/q;->a:Landroid/content/Context;

    .line 4
    .line 5
    const/4 v2, 0x2

    .line 6
    const/4 v3, 0x1

    .line 7
    const/4 v4, 0x0

    .line 8
    const/4 v5, 0x0

    .line 9
    :try_start_0
    new-instance v0, Landroid/content/IntentFilter;

    .line 10
    .line 11
    const-string v6, "android.intent.action.BATTERY_CHANGED"

    .line 12
    .line 13
    invoke-direct {v0, v6}, Landroid/content/IntentFilter;-><init>(Ljava/lang/String;)V

    .line 14
    .line 15
    .line 16
    invoke-virtual {v1, v5, v0}, Landroid/content/Context;->registerReceiver(Landroid/content/BroadcastReceiver;Landroid/content/IntentFilter;)Landroid/content/Intent;

    .line 17
    .line 18
    .line 19
    move-result-object v0

    .line 20
    if-eqz v0, :cond_4

    .line 21
    .line 22
    const-string v6, "status"

    .line 23
    .line 24
    const/4 v7, -0x1

    .line 25
    invoke-virtual {v0, v6, v7}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 26
    .line 27
    .line 28
    move-result v6
    :try_end_0
    .catch Ljava/lang/IllegalStateException; {:try_start_0 .. :try_end_0} :catch_1

    .line 29
    if-ne v6, v7, :cond_1

    .line 30
    .line 31
    :cond_0
    move v6, v4

    .line 32
    goto :goto_0

    .line 33
    :cond_1
    if-eq v6, v2, :cond_2

    .line 34
    .line 35
    const/4 v8, 0x5

    .line 36
    if-ne v6, v8, :cond_0

    .line 37
    .line 38
    :cond_2
    move v6, v3

    .line 39
    :goto_0
    :try_start_1
    const-string v8, "level"

    .line 40
    .line 41
    invoke-virtual {v0, v8, v7}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 42
    .line 43
    .line 44
    move-result v8

    .line 45
    const-string v9, "scale"

    .line 46
    .line 47
    invoke-virtual {v0, v9, v7}, Landroid/content/Intent;->getIntExtra(Ljava/lang/String;I)I

    .line 48
    .line 49
    .line 50
    move-result v0

    .line 51
    if-eq v8, v7, :cond_5

    .line 52
    .line 53
    if-ne v0, v7, :cond_3

    .line 54
    .line 55
    goto :goto_3

    .line 56
    :cond_3
    int-to-float v7, v8

    .line 57
    int-to-float v0, v0

    .line 58
    div-float/2addr v7, v0

    .line 59
    invoke-static {v7}, Ljava/lang/Float;->valueOf(F)Ljava/lang/Float;

    .line 60
    .line 61
    .line 62
    move-result-object v0
    :try_end_1
    .catch Ljava/lang/IllegalStateException; {:try_start_1 .. :try_end_1} :catch_0

    .line 63
    goto :goto_4

    .line 64
    :catch_0
    move-exception v0

    .line 65
    goto :goto_2

    .line 66
    :goto_1
    move v6, v4

    .line 67
    goto :goto_2

    .line 68
    :cond_4
    move v6, v4

    .line 69
    goto :goto_3

    .line 70
    :catch_1
    move-exception v0

    .line 71
    goto :goto_1

    .line 72
    :goto_2
    const-string v7, "An error occurred getting battery state."

    .line 73
    .line 74
    const-string v8, "FirebaseCrashlytics"

    .line 75
    .line 76
    invoke-static {v8, v7, v0}, Landroid/util/Log;->e(Ljava/lang/String;Ljava/lang/String;Ljava/lang/Throwable;)I

    .line 77
    .line 78
    .line 79
    :cond_5
    :goto_3
    move-object v0, v5

    .line 80
    :goto_4
    if-eqz v0, :cond_6

    .line 81
    .line 82
    invoke-virtual {v0}, Ljava/lang/Float;->doubleValue()D

    .line 83
    .line 84
    .line 85
    move-result-wide v7

    .line 86
    invoke-static {v7, v8}, Ljava/lang/Double;->valueOf(D)Ljava/lang/Double;

    .line 87
    .line 88
    .line 89
    move-result-object v5

    .line 90
    :cond_6
    if-eqz v6, :cond_9

    .line 91
    .line 92
    if-nez v0, :cond_7

    .line 93
    .line 94
    goto :goto_5

    .line 95
    :cond_7
    invoke-virtual {v0}, Ljava/lang/Float;->floatValue()F

    .line 96
    .line 97
    .line 98
    move-result v0

    .line 99
    float-to-double v6, v0

    .line 100
    const-wide v8, 0x3fefae147ae147aeL    # 0.99

    .line 101
    .line 102
    .line 103
    .line 104
    .line 105
    cmpg-double v0, v6, v8

    .line 106
    .line 107
    if-gez v0, :cond_8

    .line 108
    .line 109
    move v0, v2

    .line 110
    goto :goto_6

    .line 111
    :cond_8
    const/4 v0, 0x3

    .line 112
    goto :goto_6

    .line 113
    :cond_9
    :goto_5
    move v0, v3

    .line 114
    :goto_6
    invoke-static {}, Lms/f;->f()Z

    .line 115
    .line 116
    .line 117
    move-result v6

    .line 118
    const/16 v7, 0x8

    .line 119
    .line 120
    if-eqz v6, :cond_a

    .line 121
    .line 122
    goto :goto_7

    .line 123
    :cond_a
    const-string v6, "sensor"

    .line 124
    .line 125
    invoke-virtual {v1, v6}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 126
    .line 127
    .line 128
    move-result-object v6

    .line 129
    check-cast v6, Landroid/hardware/SensorManager;

    .line 130
    .line 131
    invoke-virtual {v6, v7}, Landroid/hardware/SensorManager;->getDefaultSensor(I)Landroid/hardware/Sensor;

    .line 132
    .line 133
    .line 134
    move-result-object v6

    .line 135
    if-eqz v6, :cond_b

    .line 136
    .line 137
    move v4, v3

    .line 138
    :cond_b
    :goto_7
    invoke-static {v1}, Lms/f;->a(Landroid/content/Context;)J

    .line 139
    .line 140
    .line 141
    move-result-wide v8

    .line 142
    new-instance v6, Landroid/app/ActivityManager$MemoryInfo;

    .line 143
    .line 144
    invoke-direct {v6}, Landroid/app/ActivityManager$MemoryInfo;-><init>()V

    .line 145
    .line 146
    .line 147
    const-string v10, "activity"

    .line 148
    .line 149
    invoke-virtual {v1, v10}, Landroid/content/Context;->getSystemService(Ljava/lang/String;)Ljava/lang/Object;

    .line 150
    .line 151
    .line 152
    move-result-object v1

    .line 153
    check-cast v1, Landroid/app/ActivityManager;

    .line 154
    .line 155
    invoke-virtual {v1, v6}, Landroid/app/ActivityManager;->getMemoryInfo(Landroid/app/ActivityManager$MemoryInfo;)V

    .line 156
    .line 157
    .line 158
    iget-wide v10, v6, Landroid/app/ActivityManager$MemoryInfo;->availMem:J

    .line 159
    .line 160
    sub-long/2addr v8, v10

    .line 161
    const-wide/16 v10, 0x0

    .line 162
    .line 163
    cmp-long v1, v8, v10

    .line 164
    .line 165
    if-lez v1, :cond_c

    .line 166
    .line 167
    goto :goto_8

    .line 168
    :cond_c
    move-wide v8, v10

    .line 169
    :goto_8
    invoke-static {}, Landroid/os/Environment;->getDataDirectory()Ljava/io/File;

    .line 170
    .line 171
    .line 172
    move-result-object v1

    .line 173
    invoke-virtual {v1}, Ljava/io/File;->getPath()Ljava/lang/String;

    .line 174
    .line 175
    .line 176
    move-result-object v1

    .line 177
    new-instance v6, Landroid/os/StatFs;

    .line 178
    .line 179
    invoke-direct {v6, v1}, Landroid/os/StatFs;-><init>(Ljava/lang/String;)V

    .line 180
    .line 181
    .line 182
    invoke-virtual {v6}, Landroid/os/StatFs;->getBlockSize()I

    .line 183
    .line 184
    .line 185
    move-result v1

    .line 186
    int-to-long v10, v1

    .line 187
    invoke-virtual {v6}, Landroid/os/StatFs;->getBlockCount()I

    .line 188
    .line 189
    .line 190
    move-result v1

    .line 191
    int-to-long v12, v1

    .line 192
    mul-long/2addr v12, v10

    .line 193
    invoke-virtual {v6}, Landroid/os/StatFs;->getAvailableBlocks()I

    .line 194
    .line 195
    .line 196
    move-result v1

    .line 197
    int-to-long v14, v1

    .line 198
    mul-long/2addr v10, v14

    .line 199
    sub-long/2addr v12, v10

    .line 200
    new-instance v1, Lps/a1;

    .line 201
    .line 202
    invoke-direct {v1}, Ljava/lang/Object;-><init>()V

    .line 203
    .line 204
    .line 205
    iput-object v5, v1, Lps/a1;->a:Ljava/lang/Double;

    .line 206
    .line 207
    iput v0, v1, Lps/a1;->b:I

    .line 208
    .line 209
    iget-byte v0, v1, Lps/a1;->g:B

    .line 210
    .line 211
    or-int/2addr v0, v3

    .line 212
    int-to-byte v0, v0

    .line 213
    iput-boolean v4, v1, Lps/a1;->c:Z

    .line 214
    .line 215
    or-int/2addr v0, v2

    .line 216
    int-to-byte v0, v0

    .line 217
    move/from16 v2, p1

    .line 218
    .line 219
    iput v2, v1, Lps/a1;->d:I

    .line 220
    .line 221
    or-int/lit8 v0, v0, 0x4

    .line 222
    .line 223
    int-to-byte v0, v0

    .line 224
    iput-wide v8, v1, Lps/a1;->e:J

    .line 225
    .line 226
    or-int/2addr v0, v7

    .line 227
    int-to-byte v0, v0

    .line 228
    iput-wide v12, v1, Lps/a1;->f:J

    .line 229
    .line 230
    or-int/lit8 v0, v0, 0x10

    .line 231
    .line 232
    int-to-byte v0, v0

    .line 233
    iput-byte v0, v1, Lps/a1;->g:B

    .line 234
    .line 235
    invoke-virtual {v1}, Lps/a1;->a()Lps/b1;

    .line 236
    .line 237
    .line 238
    move-result-object v0

    .line 239
    return-object v0
.end method

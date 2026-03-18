.class public abstract Lin/e2;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ljava/util/HashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 7

    .line 1
    new-instance v0, Ljava/util/HashMap;

    .line 2
    .line 3
    const/16 v1, 0xd

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ljava/util/HashMap;-><init>(I)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Lin/e2;->a:Ljava/util/HashMap;

    .line 9
    .line 10
    const/16 v1, 0x190

    .line 11
    .line 12
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 13
    .line 14
    .line 15
    move-result-object v1

    .line 16
    const-string v2, "normal"

    .line 17
    .line 18
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 19
    .line 20
    .line 21
    const/16 v2, 0x2bc

    .line 22
    .line 23
    invoke-static {v2}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 24
    .line 25
    .line 26
    move-result-object v2

    .line 27
    const-string v3, "bold"

    .line 28
    .line 29
    invoke-virtual {v0, v3, v2}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 30
    .line 31
    .line 32
    const-string v3, "lighter"

    .line 33
    .line 34
    const/4 v4, -0x1

    .line 35
    const/4 v5, 0x1

    .line 36
    const-string v6, "bolder"

    .line 37
    .line 38
    invoke-static {v5, v0, v6, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 39
    .line 40
    .line 41
    const-string v3, "200"

    .line 42
    .line 43
    const/16 v4, 0xc8

    .line 44
    .line 45
    const/16 v5, 0x64

    .line 46
    .line 47
    const-string v6, "100"

    .line 48
    .line 49
    invoke-static {v5, v0, v6, v4, v3}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 50
    .line 51
    .line 52
    const/16 v3, 0x12c

    .line 53
    .line 54
    invoke-static {v3}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 55
    .line 56
    .line 57
    move-result-object v3

    .line 58
    const-string v4, "300"

    .line 59
    .line 60
    invoke-virtual {v0, v4, v3}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 61
    .line 62
    .line 63
    const-string v3, "400"

    .line 64
    .line 65
    invoke-virtual {v0, v3, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 66
    .line 67
    .line 68
    const-string v1, "600"

    .line 69
    .line 70
    const/16 v3, 0x258

    .line 71
    .line 72
    const/16 v4, 0x1f4

    .line 73
    .line 74
    const-string v5, "500"

    .line 75
    .line 76
    invoke-static {v4, v0, v5, v3, v1}, Lcom/google/android/gms/internal/mlkit_vision_barcode_bundled/b2;->w(ILjava/util/HashMap;Ljava/lang/String;ILjava/lang/String;)V

    .line 77
    .line 78
    .line 79
    const-string v1, "800"

    .line 80
    .line 81
    const/16 v3, 0x320

    .line 82
    .line 83
    const-string v4, "700"

    .line 84
    .line 85
    invoke-static {v0, v4, v2, v3, v1}, Lvj/b;->y(Ljava/util/HashMap;Ljava/lang/String;Ljava/lang/Integer;ILjava/lang/String;)V

    .line 86
    .line 87
    .line 88
    const/16 v1, 0x384

    .line 89
    .line 90
    invoke-static {v1}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    .line 91
    .line 92
    .line 93
    move-result-object v1

    .line 94
    const-string v2, "900"

    .line 95
    .line 96
    invoke-virtual {v0, v2, v1}, Ljava/util/HashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    .line 97
    .line 98
    .line 99
    return-void
.end method

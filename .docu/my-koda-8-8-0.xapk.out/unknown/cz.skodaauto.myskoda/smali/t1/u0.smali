.class public final enum Lt1/u0;
.super Ljava/lang/Enum;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final synthetic e:[Lt1/u0;


# instance fields
.field public final d:Ljava/lang/Object;


# direct methods
.method static constructor <clinit>()V
    .locals 10

    .line 1
    new-instance v0, Lt1/u0;

    .line 2
    .line 3
    const v4, 0x1040003

    .line 4
    .line 5
    .line 6
    const v5, 0x1010311

    .line 7
    .line 8
    .line 9
    const-string v1, "Cut"

    .line 10
    .line 11
    const/4 v2, 0x0

    .line 12
    sget-object v3, Lw1/e;->a:Ljava/lang/Object;

    .line 13
    .line 14
    invoke-direct/range {v0 .. v5}, Lt1/u0;-><init>(Ljava/lang/String;ILjava/lang/Object;II)V

    .line 15
    .line 16
    .line 17
    new-instance v1, Lt1/u0;

    .line 18
    .line 19
    const v5, 0x1040001

    .line 20
    .line 21
    .line 22
    const v6, 0x1010312

    .line 23
    .line 24
    .line 25
    const-string v2, "Copy"

    .line 26
    .line 27
    const/4 v3, 0x1

    .line 28
    sget-object v4, Lw1/e;->b:Ljava/lang/Object;

    .line 29
    .line 30
    invoke-direct/range {v1 .. v6}, Lt1/u0;-><init>(Ljava/lang/String;ILjava/lang/Object;II)V

    .line 31
    .line 32
    .line 33
    new-instance v2, Lt1/u0;

    .line 34
    .line 35
    const v6, 0x104000b

    .line 36
    .line 37
    .line 38
    const v7, 0x1010313

    .line 39
    .line 40
    .line 41
    const-string v3, "Paste"

    .line 42
    .line 43
    const/4 v4, 0x2

    .line 44
    sget-object v5, Lw1/e;->c:Ljava/lang/Object;

    .line 45
    .line 46
    invoke-direct/range {v2 .. v7}, Lt1/u0;-><init>(Ljava/lang/String;ILjava/lang/Object;II)V

    .line 47
    .line 48
    .line 49
    new-instance v3, Lt1/u0;

    .line 50
    .line 51
    const v7, 0x104000d

    .line 52
    .line 53
    .line 54
    const v8, 0x101037e

    .line 55
    .line 56
    .line 57
    const-string v4, "SelectAll"

    .line 58
    .line 59
    const/4 v5, 0x3

    .line 60
    sget-object v6, Lw1/e;->d:Ljava/lang/Object;

    .line 61
    .line 62
    invoke-direct/range {v3 .. v8}, Lt1/u0;-><init>(Ljava/lang/String;ILjava/lang/Object;II)V

    .line 63
    .line 64
    .line 65
    new-instance v4, Lt1/u0;

    .line 66
    .line 67
    const v8, 0x104001a

    .line 68
    .line 69
    .line 70
    const/4 v9, 0x0

    .line 71
    const-string v5, "Autofill"

    .line 72
    .line 73
    const/4 v6, 0x4

    .line 74
    sget-object v7, Lw1/e;->e:Ljava/lang/Object;

    .line 75
    .line 76
    invoke-direct/range {v4 .. v9}, Lt1/u0;-><init>(Ljava/lang/String;ILjava/lang/Object;II)V

    .line 77
    .line 78
    .line 79
    filled-new-array {v0, v1, v2, v3, v4}, [Lt1/u0;

    .line 80
    .line 81
    .line 82
    move-result-object v0

    .line 83
    sput-object v0, Lt1/u0;->e:[Lt1/u0;

    .line 84
    .line 85
    invoke-static {v0}, Lkp/u8;->b([Ljava/lang/Enum;)Lsx0/b;

    .line 86
    .line 87
    .line 88
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;ILjava/lang/Object;II)V
    .locals 0

    .line 1
    invoke-direct {p0, p1, p2}, Ljava/lang/Enum;-><init>(Ljava/lang/String;I)V

    .line 2
    .line 3
    .line 4
    iput-object p3, p0, Lt1/u0;->d:Ljava/lang/Object;

    .line 5
    .line 6
    return-void
.end method

.method public static valueOf(Ljava/lang/String;)Lt1/u0;
    .locals 1

    .line 1
    const-class v0, Lt1/u0;

    .line 2
    .line 3
    invoke-static {v0, p0}, Ljava/lang/Enum;->valueOf(Ljava/lang/Class;Ljava/lang/String;)Ljava/lang/Enum;

    .line 4
    .line 5
    .line 6
    move-result-object p0

    .line 7
    check-cast p0, Lt1/u0;

    .line 8
    .line 9
    return-object p0
.end method

.method public static values()[Lt1/u0;
    .locals 1

    .line 1
    sget-object v0, Lt1/u0;->e:[Lt1/u0;

    .line 2
    .line 3
    invoke-virtual {v0}, Ljava/lang/Object;->clone()Ljava/lang/Object;

    .line 4
    .line 5
    .line 6
    move-result-object v0

    .line 7
    check-cast v0, [Lt1/u0;

    .line 8
    .line 9
    return-object v0
.end method

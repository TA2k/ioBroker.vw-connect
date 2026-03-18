.class public abstract Ly40/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Ly40/b;

.field public static final b:Leo0/b;

.field public static final c:Leo0/b;

.field public static final d:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    new-instance v0, Ly40/b;

    .line 2
    .line 3
    const-string v1, "poi_picker_map"

    .line 4
    .line 5
    invoke-direct {v0, v1}, Ly40/b;-><init>(Ljava/lang/String;)V

    .line 6
    .line 7
    .line 8
    sput-object v0, Ly40/c;->a:Ly40/b;

    .line 9
    .line 10
    new-instance v0, Leo0/b;

    .line 11
    .line 12
    const/4 v2, 0x3

    .line 13
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 14
    .line 15
    .line 16
    sput-object v0, Ly40/c;->b:Leo0/b;

    .line 17
    .line 18
    new-instance v0, Leo0/b;

    .line 19
    .line 20
    const/4 v2, 0x1

    .line 21
    invoke-direct {v0, v1, v2}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 22
    .line 23
    .line 24
    sput-object v0, Ly40/c;->c:Leo0/b;

    .line 25
    .line 26
    new-instance v0, Lxy/f;

    .line 27
    .line 28
    const/4 v1, 0x3

    .line 29
    invoke-direct {v0, v1}, Lxy/f;-><init>(I)V

    .line 30
    .line 31
    .line 32
    new-instance v1, Le21/a;

    .line 33
    .line 34
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 35
    .line 36
    .line 37
    invoke-virtual {v0, v1}, Lxy/f;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 38
    .line 39
    .line 40
    sput-object v1, Ly40/c;->d:Le21/a;

    .line 41
    .line 42
    return-void
.end method

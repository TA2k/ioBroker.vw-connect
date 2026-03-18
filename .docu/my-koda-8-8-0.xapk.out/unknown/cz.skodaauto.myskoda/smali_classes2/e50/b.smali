.class public abstract Le50/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Leo0/b;

.field public static final b:Leo0/b;

.field public static final c:Leo0/b;

.field public static final d:Leo0/b;

.field public static final e:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Leo0/b;

    .line 2
    .line 3
    const/4 v1, 0x3

    .line 4
    const-string v2, "route_map"

    .line 5
    .line 6
    invoke-direct {v0, v2, v1}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 7
    .line 8
    .line 9
    sput-object v0, Le50/b;->a:Leo0/b;

    .line 10
    .line 11
    new-instance v0, Leo0/b;

    .line 12
    .line 13
    const-string v1, "add_stop_map"

    .line 14
    .line 15
    const/4 v3, 0x3

    .line 16
    invoke-direct {v0, v1, v3}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    sput-object v0, Le50/b;->b:Leo0/b;

    .line 20
    .line 21
    new-instance v0, Leo0/b;

    .line 22
    .line 23
    const/4 v1, 0x2

    .line 24
    invoke-direct {v0, v2, v1}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 25
    .line 26
    .line 27
    sput-object v0, Le50/b;->c:Leo0/b;

    .line 28
    .line 29
    new-instance v0, Leo0/b;

    .line 30
    .line 31
    const/4 v1, 0x4

    .line 32
    invoke-direct {v0, v2, v1}, Leo0/b;-><init>(Ljava/lang/String;I)V

    .line 33
    .line 34
    .line 35
    sput-object v0, Le50/b;->d:Leo0/b;

    .line 36
    .line 37
    new-instance v0, Ldj/a;

    .line 38
    .line 39
    const/16 v1, 0x15

    .line 40
    .line 41
    invoke-direct {v0, v1}, Ldj/a;-><init>(I)V

    .line 42
    .line 43
    .line 44
    new-instance v1, Le21/a;

    .line 45
    .line 46
    invoke-direct {v1}, Le21/a;-><init>()V

    .line 47
    .line 48
    .line 49
    invoke-virtual {v0, v1}, Ldj/a;->invoke(Ljava/lang/Object;)Ljava/lang/Object;

    .line 50
    .line 51
    .line 52
    sput-object v1, Le50/b;->e:Le21/a;

    .line 53
    .line 54
    return-void
.end method

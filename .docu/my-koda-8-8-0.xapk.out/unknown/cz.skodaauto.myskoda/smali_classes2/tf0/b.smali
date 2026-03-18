.class public abstract Ltf0/b;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final a:Le21/a;


# direct methods
.method static constructor <clinit>()V
    .locals 12

    .line 1
    new-instance v0, Le21/a;

    .line 2
    .line 3
    invoke-direct {v0}, Le21/a;-><init>()V

    .line 4
    .line 5
    .line 6
    new-instance v5, Ltf0/a;

    .line 7
    .line 8
    const/4 v1, 0x0

    .line 9
    invoke-direct {v5, v1}, Ltf0/a;-><init>(I)V

    .line 10
    .line 11
    .line 12
    sget-object v2, Li21/b;->e:Lh21/b;

    .line 13
    .line 14
    sget-object v6, La21/c;->d:La21/c;

    .line 15
    .line 16
    new-instance v1, La21/a;

    .line 17
    .line 18
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 19
    .line 20
    const-class v3, Lxf0/a;

    .line 21
    .line 22
    invoke-virtual {v7, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 23
    .line 24
    .line 25
    move-result-object v3

    .line 26
    const/4 v4, 0x0

    .line 27
    invoke-direct/range {v1 .. v6}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 28
    .line 29
    .line 30
    new-instance v3, Lc21/d;

    .line 31
    .line 32
    invoke-direct {v3, v1}, Lc21/b;-><init>(La21/a;)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {v0, v3}, Le21/a;->a(Lc21/b;)V

    .line 36
    .line 37
    .line 38
    new-instance v10, Lt40/b;

    .line 39
    .line 40
    const/16 v1, 0x1a

    .line 41
    .line 42
    invoke-direct {v10, v1}, Lt40/b;-><init>(I)V

    .line 43
    .line 44
    .line 45
    move-object v11, v6

    .line 46
    new-instance v6, La21/a;

    .line 47
    .line 48
    const-class v1, Lsf0/a;

    .line 49
    .line 50
    invoke-virtual {v7, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 51
    .line 52
    .line 53
    move-result-object v8

    .line 54
    const/4 v9, 0x0

    .line 55
    move-object v7, v2

    .line 56
    invoke-direct/range {v6 .. v11}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 57
    .line 58
    .line 59
    invoke-static {v6, v0}, Lf2/m0;->t(La21/a;Le21/a;)V

    .line 60
    .line 61
    .line 62
    sput-object v0, Ltf0/b;->a:Le21/a;

    .line 63
    .line 64
    return-void
.end method

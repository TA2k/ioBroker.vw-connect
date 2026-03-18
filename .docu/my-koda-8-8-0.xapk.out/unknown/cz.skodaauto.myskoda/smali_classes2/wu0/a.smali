.class public abstract Lwu0/a;
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
    new-instance v5, Lvq0/a;

    .line 7
    .line 8
    const/16 v1, 0x1c

    .line 9
    .line 10
    invoke-direct {v5, v1}, Lvq0/a;-><init>(I)V

    .line 11
    .line 12
    .line 13
    sget-object v2, Li21/b;->e:Lh21/b;

    .line 14
    .line 15
    sget-object v6, La21/c;->e:La21/c;

    .line 16
    .line 17
    new-instance v1, La21/a;

    .line 18
    .line 19
    sget-object v7, Lkotlin/jvm/internal/g0;->a:Lkotlin/jvm/internal/h0;

    .line 20
    .line 21
    const-class v3, Ldv0/e;

    .line 22
    .line 23
    invoke-virtual {v7, v3}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 24
    .line 25
    .line 26
    move-result-object v3

    .line 27
    const/4 v4, 0x0

    .line 28
    invoke-direct/range {v1 .. v6}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 29
    .line 30
    .line 31
    new-instance v3, Lc21/a;

    .line 32
    .line 33
    invoke-direct {v3, v1}, Lc21/b;-><init>(La21/a;)V

    .line 34
    .line 35
    .line 36
    invoke-virtual {v0, v3}, Le21/a;->a(Lc21/b;)V

    .line 37
    .line 38
    .line 39
    new-instance v10, Lvq0/a;

    .line 40
    .line 41
    const/16 v1, 0x1b

    .line 42
    .line 43
    invoke-direct {v10, v1}, Lvq0/a;-><init>(I)V

    .line 44
    .line 45
    .line 46
    move-object v11, v6

    .line 47
    new-instance v6, La21/a;

    .line 48
    .line 49
    const-class v1, Lxu0/b;

    .line 50
    .line 51
    invoke-virtual {v7, v1}, Lkotlin/jvm/internal/h0;->getOrCreateKotlinClass(Ljava/lang/Class;)Lhy0/d;

    .line 52
    .line 53
    .line 54
    move-result-object v8

    .line 55
    const/4 v9, 0x0

    .line 56
    move-object v7, v2

    .line 57
    invoke-direct/range {v6 .. v11}, La21/a;-><init>(Lh21/a;Lhy0/d;Lh21/b;Lay0/n;La21/c;)V

    .line 58
    .line 59
    .line 60
    invoke-static {v6, v0}, Lvj/b;->v(La21/a;Le21/a;)V

    .line 61
    .line 62
    .line 63
    sput-object v0, Lwu0/a;->a:Le21/a;

    .line 64
    .line 65
    return-void
.end method

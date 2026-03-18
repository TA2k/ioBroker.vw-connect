.class public final Lw40/m;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final r:J

.field public static final synthetic s:I


# instance fields
.field public final h:Ltr0/b;

.field public final i:Lnn0/f;

.field public final j:Lu40/c;

.field public final k:Lud0/b;

.field public final l:Lrq0/f;

.field public final m:Ljn0/c;

.field public final n:Lnn0/m;

.field public final o:Lu40/l;

.field public final p:Lij0/a;

.field public q:Lvy0/x1;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    sget v0, Lmy0/c;->g:I

    .line 2
    .line 3
    const/4 v0, 0x1

    .line 4
    sget-object v1, Lmy0/e;->i:Lmy0/e;

    .line 5
    .line 6
    invoke-static {v0, v1}, Lmy0/h;->s(ILmy0/e;)J

    .line 7
    .line 8
    .line 9
    move-result-wide v0

    .line 10
    sput-wide v0, Lw40/m;->r:J

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Ltr0/b;Lnn0/f;Lu40/c;Lud0/b;Lrq0/f;Ljn0/c;Lnn0/m;Lu40/l;Lij0/a;)V
    .locals 17

    .line 1
    move-object/from16 v0, p0

    .line 2
    .line 3
    new-instance v1, Lw40/l;

    .line 4
    .line 5
    const/4 v14, 0x0

    .line 6
    const/4 v15, 0x0

    .line 7
    const-string v2, ""

    .line 8
    .line 9
    const/4 v10, 0x0

    .line 10
    const/4 v11, 0x0

    .line 11
    const/4 v12, 0x0

    .line 12
    const/4 v13, 0x0

    .line 13
    const/16 v16, 0x0

    .line 14
    .line 15
    move-object v3, v2

    .line 16
    move-object v4, v2

    .line 17
    move-object v5, v2

    .line 18
    move-object v6, v2

    .line 19
    move-object v7, v2

    .line 20
    move-object v8, v2

    .line 21
    move-object v9, v2

    .line 22
    invoke-direct/range {v1 .. v16}, Lw40/l;-><init>(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ZZZZZZLql0/g;)V

    .line 23
    .line 24
    .line 25
    invoke-direct {v0, v1}, Lql0/j;-><init>(Lql0/h;)V

    .line 26
    .line 27
    .line 28
    move-object/from16 v1, p1

    .line 29
    .line 30
    iput-object v1, v0, Lw40/m;->h:Ltr0/b;

    .line 31
    .line 32
    move-object/from16 v1, p2

    .line 33
    .line 34
    iput-object v1, v0, Lw40/m;->i:Lnn0/f;

    .line 35
    .line 36
    move-object/from16 v1, p3

    .line 37
    .line 38
    iput-object v1, v0, Lw40/m;->j:Lu40/c;

    .line 39
    .line 40
    move-object/from16 v1, p4

    .line 41
    .line 42
    iput-object v1, v0, Lw40/m;->k:Lud0/b;

    .line 43
    .line 44
    move-object/from16 v1, p5

    .line 45
    .line 46
    iput-object v1, v0, Lw40/m;->l:Lrq0/f;

    .line 47
    .line 48
    move-object/from16 v1, p6

    .line 49
    .line 50
    iput-object v1, v0, Lw40/m;->m:Ljn0/c;

    .line 51
    .line 52
    move-object/from16 v1, p7

    .line 53
    .line 54
    iput-object v1, v0, Lw40/m;->n:Lnn0/m;

    .line 55
    .line 56
    move-object/from16 v1, p8

    .line 57
    .line 58
    iput-object v1, v0, Lw40/m;->o:Lu40/l;

    .line 59
    .line 60
    move-object/from16 v1, p9

    .line 61
    .line 62
    iput-object v1, v0, Lw40/m;->p:Lij0/a;

    .line 63
    .line 64
    new-instance v1, Lw40/k;

    .line 65
    .line 66
    const/4 v2, 0x0

    .line 67
    const/4 v3, 0x0

    .line 68
    invoke-direct {v1, v0, v2, v3}, Lw40/k;-><init>(Lw40/m;Lkotlin/coroutines/Continuation;I)V

    .line 69
    .line 70
    .line 71
    invoke-virtual {v0, v1}, Lql0/j;->b(Lay0/n;)V

    .line 72
    .line 73
    .line 74
    return-void
.end method

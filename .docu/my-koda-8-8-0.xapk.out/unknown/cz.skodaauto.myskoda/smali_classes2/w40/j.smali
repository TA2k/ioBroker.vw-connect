.class public final Lw40/j;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final m:J

.field public static final synthetic n:I


# instance fields
.field public final h:Lu40/o;

.field public final i:Lnn0/t;

.field public final j:Lnn0/m;

.field public final k:Lij0/a;

.field public l:Lvy0/x1;


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
    sput-wide v0, Lw40/j;->m:J

    .line 11
    .line 12
    return-void
.end method

.method public constructor <init>(Lu40/o;Lnn0/t;Lnn0/m;Lij0/a;)V
    .locals 1

    .line 1
    new-instance v0, Lw40/i;

    .line 2
    .line 3
    invoke-direct {v0}, Lw40/i;-><init>()V

    .line 4
    .line 5
    .line 6
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 7
    .line 8
    .line 9
    iput-object p1, p0, Lw40/j;->h:Lu40/o;

    .line 10
    .line 11
    iput-object p2, p0, Lw40/j;->i:Lnn0/t;

    .line 12
    .line 13
    iput-object p3, p0, Lw40/j;->j:Lnn0/m;

    .line 14
    .line 15
    iput-object p4, p0, Lw40/j;->k:Lij0/a;

    .line 16
    .line 17
    new-instance p1, Lvo0/e;

    .line 18
    .line 19
    const/4 p2, 0x0

    .line 20
    const/4 p3, 0x7

    .line 21
    invoke-direct {p1, p0, p2, p3}, Lvo0/e;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 22
    .line 23
    .line 24
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 25
    .line 26
    .line 27
    return-void
.end method

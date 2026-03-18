.class public final Lba0/g;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# instance fields
.field public final h:Lws0/a;

.field public final i:Ltr0/b;

.field public final j:Lz90/m;

.field public final k:Lkf0/z;

.field public final l:Lij0/a;

.field public final m:Lz90/l;


# direct methods
.method public constructor <init>(Lws0/a;Ltr0/b;Lz90/m;Lkf0/z;Lij0/a;Lz90/l;)V
    .locals 7

    .line 1
    new-instance v0, Lba0/f;

    .line 2
    .line 3
    const/4 v5, 0x0

    .line 4
    const/4 v6, 0x0

    .line 5
    const-string v1, ""

    .line 6
    .line 7
    const/4 v3, 0x0

    .line 8
    const/4 v4, 0x0

    .line 9
    move-object v2, v1

    .line 10
    invoke-direct/range {v0 .. v6}, Lba0/f;-><init>(Ljava/lang/String;Ljava/lang/String;Lql0/g;ZZZ)V

    .line 11
    .line 12
    .line 13
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 14
    .line 15
    .line 16
    iput-object p1, p0, Lba0/g;->h:Lws0/a;

    .line 17
    .line 18
    iput-object p2, p0, Lba0/g;->i:Ltr0/b;

    .line 19
    .line 20
    iput-object p3, p0, Lba0/g;->j:Lz90/m;

    .line 21
    .line 22
    iput-object p4, p0, Lba0/g;->k:Lkf0/z;

    .line 23
    .line 24
    iput-object p5, p0, Lba0/g;->l:Lij0/a;

    .line 25
    .line 26
    iput-object p6, p0, Lba0/g;->m:Lz90/l;

    .line 27
    .line 28
    new-instance p1, La50/a;

    .line 29
    .line 30
    const/4 p2, 0x0

    .line 31
    const/4 p3, 0x7

    .line 32
    invoke-direct {p1, p0, p2, p3}, La50/a;-><init>(Ljava/lang/Object;Lkotlin/coroutines/Continuation;I)V

    .line 33
    .line 34
    .line 35
    invoke-virtual {p0, p1}, Lql0/j;->b(Lay0/n;)V

    .line 36
    .line 37
    .line 38
    return-void
.end method

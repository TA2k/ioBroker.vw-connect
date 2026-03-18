.class public final Lbo0/b;
.super Lql0/j;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final j:Lgy0/j;


# instance fields
.field public final h:Lyn0/k;

.field public final i:Ltr0/b;


# direct methods
.method static constructor <clinit>()V
    .locals 4

    .line 1
    new-instance v0, Lgy0/j;

    .line 2
    .line 3
    const/16 v1, 0x64

    .line 4
    .line 5
    const/4 v2, 0x1

    .line 6
    const/16 v3, 0x32

    .line 7
    .line 8
    invoke-direct {v0, v3, v1, v2}, Lgy0/h;-><init>(III)V

    .line 9
    .line 10
    .line 11
    sput-object v0, Lbo0/b;->j:Lgy0/j;

    .line 12
    .line 13
    return-void
.end method

.method public constructor <init>(Lyn0/b;Lyn0/k;Ltr0/b;)V
    .locals 3

    .line 1
    new-instance v0, Lbo0/a;

    .line 2
    .line 3
    sget-object v1, Lbo0/b;->j:Lgy0/j;

    .line 4
    .line 5
    iget v2, v1, Lgy0/h;->d:I

    .line 6
    .line 7
    invoke-direct {v0, v2, v1}, Lbo0/a;-><init>(ILgy0/j;)V

    .line 8
    .line 9
    .line 10
    invoke-direct {p0, v0}, Lql0/j;-><init>(Lql0/h;)V

    .line 11
    .line 12
    .line 13
    iput-object p2, p0, Lbo0/b;->h:Lyn0/k;

    .line 14
    .line 15
    iput-object p3, p0, Lbo0/b;->i:Ltr0/b;

    .line 16
    .line 17
    new-instance p2, La50/c;

    .line 18
    .line 19
    const/4 p3, 0x0

    .line 20
    const/16 v0, 0xc

    .line 21
    .line 22
    invoke-direct {p2, v0, p1, p0, p3}, La50/c;-><init>(ILjava/lang/Object;Ljava/lang/Object;Lkotlin/coroutines/Continuation;)V

    .line 23
    .line 24
    .line 25
    invoke-virtual {p0, p2}, Lql0/j;->b(Lay0/n;)V

    .line 26
    .line 27
    .line 28
    return-void
.end method

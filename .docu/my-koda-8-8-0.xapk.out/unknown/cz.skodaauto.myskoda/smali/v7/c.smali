.class public final Lv7/c;
.super Ljava/lang/Object;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final b:Lhr/p;

.field public static final c:Lv7/c;


# instance fields
.field public final a:Lhr/x0;


# direct methods
.method static constructor <clinit>()V
    .locals 3

    .line 1
    sget-object v0, Lhr/v0;->e:Lhr/v0;

    .line 2
    .line 3
    new-instance v1, Lt0/c;

    .line 4
    .line 5
    const/16 v2, 0xa

    .line 6
    .line 7
    invoke-direct {v1, v2}, Lt0/c;-><init>(I)V

    .line 8
    .line 9
    .line 10
    new-instance v2, Lhr/p;

    .line 11
    .line 12
    invoke-direct {v2, v1, v0}, Lhr/p;-><init>(Lgr/e;Lhr/w0;)V

    .line 13
    .line 14
    .line 15
    sput-object v2, Lv7/c;->b:Lhr/p;

    .line 16
    .line 17
    new-instance v0, Lv7/c;

    .line 18
    .line 19
    sget-object v1, Lhr/h0;->e:Lhr/f0;

    .line 20
    .line 21
    sget-object v1, Lhr/x0;->h:Lhr/x0;

    .line 22
    .line 23
    invoke-direct {v0, v1}, Lv7/c;-><init>(Ljava/util/List;)V

    .line 24
    .line 25
    .line 26
    sput-object v0, Lv7/c;->c:Lv7/c;

    .line 27
    .line 28
    const/4 v0, 0x0

    .line 29
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 30
    .line 31
    .line 32
    const/4 v0, 0x1

    .line 33
    invoke-static {v0}, Lw7/w;->z(I)V

    .line 34
    .line 35
    .line 36
    return-void
.end method

.method public constructor <init>(Ljava/util/List;)V
    .locals 1

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    .line 3
    .line 4
    sget-object v0, Lv7/c;->b:Lhr/p;

    .line 5
    .line 6
    check-cast p1, Ljava/util/List;

    .line 7
    .line 8
    invoke-static {v0, p1}, Lhr/h0;->x(Lhr/w0;Ljava/util/List;)Lhr/x0;

    .line 9
    .line 10
    .line 11
    move-result-object p1

    .line 12
    iput-object p1, p0, Lv7/c;->a:Lhr/x0;

    .line 13
    .line 14
    return-void
.end method

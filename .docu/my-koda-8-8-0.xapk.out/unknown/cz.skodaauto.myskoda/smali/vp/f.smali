.class public final Lvp/f;
.super Loo/a;
.source "r8-map-id-1fa22ea49be2480a30a121afc59f45dd19d13c43db05f668c8c507f854c1bc92"


# static fields
.field public static final CREATOR:Landroid/os/Parcelable$Creator;
    .annotation system Ldalvik/annotation/Signature;
        value = {
            "Landroid/os/Parcelable$Creator<",
            "Lvp/f;",
            ">;"
        }
    .end annotation
.end field


# instance fields
.field public d:Ljava/lang/String;

.field public e:Ljava/lang/String;

.field public f:Lvp/b4;

.field public g:J

.field public h:Z

.field public i:Ljava/lang/String;

.field public final j:Lvp/t;

.field public k:J

.field public l:Lvp/t;

.field public final m:J

.field public final n:Lvp/t;


# direct methods
.method static constructor <clinit>()V
    .locals 2

    .line 1
    new-instance v0, Ltt/f;

    .line 2
    .line 3
    const/4 v1, 0x2

    .line 4
    invoke-direct {v0, v1}, Ltt/f;-><init>(I)V

    .line 5
    .line 6
    .line 7
    sput-object v0, Lvp/f;->CREATOR:Landroid/os/Parcelable$Creator;

    .line 8
    .line 9
    return-void
.end method

.method public constructor <init>(Ljava/lang/String;Ljava/lang/String;Lvp/b4;JZLjava/lang/String;Lvp/t;JLvp/t;JLvp/t;)V
    .locals 0

    .line 1
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 2
    iput-object p1, p0, Lvp/f;->d:Ljava/lang/String;

    iput-object p2, p0, Lvp/f;->e:Ljava/lang/String;

    iput-object p3, p0, Lvp/f;->f:Lvp/b4;

    iput-wide p4, p0, Lvp/f;->g:J

    iput-boolean p6, p0, Lvp/f;->h:Z

    iput-object p7, p0, Lvp/f;->i:Ljava/lang/String;

    iput-object p8, p0, Lvp/f;->j:Lvp/t;

    iput-wide p9, p0, Lvp/f;->k:J

    iput-object p11, p0, Lvp/f;->l:Lvp/t;

    iput-wide p12, p0, Lvp/f;->m:J

    iput-object p14, p0, Lvp/f;->n:Lvp/t;

    return-void
.end method

.method public constructor <init>(Lvp/f;)V
    .locals 2

    .line 3
    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    .line 4
    invoke-static {p1}, Lno/c0;->h(Ljava/lang/Object;)V

    .line 5
    iget-object v0, p1, Lvp/f;->d:Ljava/lang/String;

    iput-object v0, p0, Lvp/f;->d:Ljava/lang/String;

    .line 6
    iget-object v0, p1, Lvp/f;->e:Ljava/lang/String;

    iput-object v0, p0, Lvp/f;->e:Ljava/lang/String;

    .line 7
    iget-object v0, p1, Lvp/f;->f:Lvp/b4;

    iput-object v0, p0, Lvp/f;->f:Lvp/b4;

    .line 8
    iget-wide v0, p1, Lvp/f;->g:J

    iput-wide v0, p0, Lvp/f;->g:J

    .line 9
    iget-boolean v0, p1, Lvp/f;->h:Z

    iput-boolean v0, p0, Lvp/f;->h:Z

    .line 10
    iget-object v0, p1, Lvp/f;->i:Ljava/lang/String;

    iput-object v0, p0, Lvp/f;->i:Ljava/lang/String;

    .line 11
    iget-object v0, p1, Lvp/f;->j:Lvp/t;

    iput-object v0, p0, Lvp/f;->j:Lvp/t;

    .line 12
    iget-wide v0, p1, Lvp/f;->k:J

    iput-wide v0, p0, Lvp/f;->k:J

    .line 13
    iget-object v0, p1, Lvp/f;->l:Lvp/t;

    iput-object v0, p0, Lvp/f;->l:Lvp/t;

    .line 14
    iget-wide v0, p1, Lvp/f;->m:J

    iput-wide v0, p0, Lvp/f;->m:J

    .line 15
    iget-object p1, p1, Lvp/f;->n:Lvp/t;

    iput-object p1, p0, Lvp/f;->n:Lvp/t;

    return-void
.end method


# virtual methods
.method public final writeToParcel(Landroid/os/Parcel;I)V
    .locals 6

    .line 1
    const/16 v0, 0x4f45

    .line 2
    .line 3
    invoke-static {p1, v0}, Ljp/dc;->s(Landroid/os/Parcel;I)I

    .line 4
    .line 5
    .line 6
    move-result v0

    .line 7
    const/4 v1, 0x2

    .line 8
    iget-object v2, p0, Lvp/f;->d:Ljava/lang/String;

    .line 9
    .line 10
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 11
    .line 12
    .line 13
    const/4 v1, 0x3

    .line 14
    iget-object v2, p0, Lvp/f;->e:Ljava/lang/String;

    .line 15
    .line 16
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 17
    .line 18
    .line 19
    iget-object v1, p0, Lvp/f;->f:Lvp/b4;

    .line 20
    .line 21
    const/4 v2, 0x4

    .line 22
    invoke-static {p1, v2, v1, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 23
    .line 24
    .line 25
    iget-wide v3, p0, Lvp/f;->g:J

    .line 26
    .line 27
    const/4 v1, 0x5

    .line 28
    const/16 v5, 0x8

    .line 29
    .line 30
    invoke-static {p1, v1, v5}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 31
    .line 32
    .line 33
    invoke-virtual {p1, v3, v4}, Landroid/os/Parcel;->writeLong(J)V

    .line 34
    .line 35
    .line 36
    iget-boolean v1, p0, Lvp/f;->h:Z

    .line 37
    .line 38
    const/4 v3, 0x6

    .line 39
    invoke-static {p1, v3, v2}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 40
    .line 41
    .line 42
    invoke-virtual {p1, v1}, Landroid/os/Parcel;->writeInt(I)V

    .line 43
    .line 44
    .line 45
    const/4 v1, 0x7

    .line 46
    iget-object v2, p0, Lvp/f;->i:Ljava/lang/String;

    .line 47
    .line 48
    invoke-static {p1, v2, v1}, Ljp/dc;->n(Landroid/os/Parcel;Ljava/lang/String;I)V

    .line 49
    .line 50
    .line 51
    iget-object v1, p0, Lvp/f;->j:Lvp/t;

    .line 52
    .line 53
    invoke-static {p1, v5, v1, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 54
    .line 55
    .line 56
    iget-wide v1, p0, Lvp/f;->k:J

    .line 57
    .line 58
    const/16 v3, 0x9

    .line 59
    .line 60
    invoke-static {p1, v3, v5}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 61
    .line 62
    .line 63
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 64
    .line 65
    .line 66
    const/16 v1, 0xa

    .line 67
    .line 68
    iget-object v2, p0, Lvp/f;->l:Lvp/t;

    .line 69
    .line 70
    invoke-static {p1, v1, v2, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 71
    .line 72
    .line 73
    const/16 v1, 0xb

    .line 74
    .line 75
    invoke-static {p1, v1, v5}, Ljp/dc;->u(Landroid/os/Parcel;II)V

    .line 76
    .line 77
    .line 78
    iget-wide v1, p0, Lvp/f;->m:J

    .line 79
    .line 80
    invoke-virtual {p1, v1, v2}, Landroid/os/Parcel;->writeLong(J)V

    .line 81
    .line 82
    .line 83
    const/16 v1, 0xc

    .line 84
    .line 85
    iget-object p0, p0, Lvp/f;->n:Lvp/t;

    .line 86
    .line 87
    invoke-static {p1, v1, p0, p2}, Ljp/dc;->m(Landroid/os/Parcel;ILandroid/os/Parcelable;I)V

    .line 88
    .line 89
    .line 90
    invoke-static {p1, v0}, Ljp/dc;->t(Landroid/os/Parcel;I)V

    .line 91
    .line 92
    .line 93
    return-void
.end method
